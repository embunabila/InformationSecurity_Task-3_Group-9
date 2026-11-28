"""Routes for managing the current user's RSA keypair."""

import io
import secrets

from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import sqlite3

from flask import (
    Blueprint,
    current_app,
    send_file,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from db import get_user_by_id, record_signature_event
from werkzeug.utils import secure_filename
from share_errors import KeyUnlockError
from web_utils import current_user_id, require_csrf


keys_bp = Blueprint("keys", __name__)


VERIFICATION_ERROR_MESSAGE = (
    "Paket kunci atau password tidak dapat diverifikasi."
)

DUPLICATE_KEY_MESSAGE = (
    "You already have a keypair."
)

SERVER_ERROR_MESSAGE = (
    "Your keys could not be accessed. Please try again later."
)


@keys_bp.after_request
def _prevent_key_page_caching(response):
    """Prevent key management responses from being cached."""
    response.headers["Cache-Control"] = "no-store"
    return response


def _ensure_csrf_token() -> str:
    """Ensure a CSRF token is available for the page forms."""

    token = session.get("csrf_token")

    if not isinstance(token, str) or not token:
        token = secrets.token_hex(32)
        session["csrf_token"] = token

    return token


def _render_keys(keypair, error=None, status=200):
    """Render the key management page without sensitive data."""

    try:
        signing_key = _signing_key_for_display(
            current_user_id()
        )
    except Exception:
        current_app.logger.error(
            "Unable to read signing key information."
        )
        return _server_error()

    return (
        render_template(
            "keys.html",
            keypair=keypair,
            signing_key=signing_key,
            error=error,
            csrf_token=_ensure_csrf_token(),
        ),
        status,
    )


def _server_error():
    """Return a generic response without internal error details."""

    return make_response(
        SERVER_ERROR_MESSAGE,
        503,
    )


@keys_bp.route("/keys", methods=["GET"])
def my_keys():
    """Display the current user's keypair status."""

    from user_keys import get_public_key

    user_id = current_user_id()

    if user_id is None:
        return redirect(url_for("login"))

    try:
        user = get_user_by_id(user_id)

        if user is None:
            session.clear()
            return redirect(url_for("login"))

        keypair = get_public_key(user_id)

    except sqlite3.Error:
        return _server_error()

    return _render_keys(keypair)


@keys_bp.route("/keys/generate", methods=["POST"])
def generate_keys():
    """Generate a keypair for the authenticated user."""

    from user_keys import (
        generate_user_keypair,
        get_public_key,
    )

    user_id = current_user_id()

    if user_id is None:
        return redirect(url_for("login"))

    # Reject invalid CSRF tokens before any database or crypto operation.
    require_csrf()

    try:
        user = get_user_by_id(user_id)

        if user is None:
            session.clear()
            return redirect(url_for("login"))

        # Check whether the current user already has a keypair.
        keypair = get_public_key(user_id)

        if keypair is not None:
            return _render_keys(
                keypair,
                error=DUPLICATE_KEY_MESSAGE,
                status=409,
            )

        # Preserve the exact submitted password.
        password = request.form.get("password", "")

        if not password:
            return _render_keys(
                None,
                error=VERIFICATION_ERROR_MESSAGE,
                status=400,
            )

        # Reuse the existing cryptographic service.
        generate_user_keypair(
            user_id,
            password,
        )

    except KeyUnlockError:
        return _render_keys(
            None,
            error=VERIFICATION_ERROR_MESSAGE,
            status=400,
        )

    except ValueError:
        # A concurrent request may have generated a keypair
        # after the initial ownership check.
        try:
            keypair = get_public_key(user_id)

        except sqlite3.Error:
            return _server_error()

        if keypair is not None:
            return _render_keys(
                keypair,
                error=DUPLICATE_KEY_MESSAGE,
                status=409,
            )

        # Do not expose unexpected validation or crypto errors.
        return _server_error()

    except (sqlite3.Error, OSError, MemoryError):
        return _server_error()

    flash(
        "Your keypair has been generated successfully.",
        "keys-success",
    )

    return redirect(
        url_for("keys.my_keys"),
        code=303,
    )

# ============================================================
# Stage 8: Signing key page and certificate routes
# ============================================================

_SIGNING_DUPLICATE_MESSAGE = (
    "You already have a signing keypair."
)

_SIGNING_PASSWORD_ERROR_MESSAGE = (
    "Password tidak dapat diverifikasi."
)

_SIGNING_SUCCESS_MESSAGE = (
    "Your signing keypair has been generated successfully."
)

_SIGNING_AUDIT_ERROR_MESSAGE = (
    "Your signing key was created, but its audit record "
    "could not be saved. Please contact support."
)

_CERTIFICATE_MIME_TYPE = "application/pkix-cert"

_DISPLAY_TIMEZONE = ZoneInfo("Asia/Jakarta")


def _keys_utc_now():
    """Current UTC time at the application's signing precision."""

    return datetime.now(timezone.utc).replace(
        microsecond=0
    )


def _format_certificate_time(value):
    """Display certificate timestamps in WIB."""

    return value.astimezone(
        _DISPLAY_TIMEZONE
    ).strftime(
        "%d %b %Y, %H:%M:%S WIB"
    )


def _signing_key_for_display(user_id):
    """Return only the public metadata needed by the template."""

    from signing_keys import get_signing_key
    from certificate import parse_certificate

    key = get_signing_key(user_id)

    if key is None:
        return None

    certificate = parse_certificate(
        key["certificate_der"]
    )

    expires_at = datetime.fromisoformat(
        key["expires_at"]
    )

    if (
        expires_at.tzinfo is None
        or expires_at.utcoffset()
        != timezone.utc.utcoffset(expires_at)
    ):
        raise ValueError(
            "Invalid certificate expiry timestamp"
        )

    if expires_at != certificate["not_after"]:
        raise ValueError(
            "Certificate expiry metadata mismatch"
        )

    now = _keys_utc_now()

    if now > expires_at:
        validity_status = "Expired"

    elif now < certificate["not_before"]:
        validity_status = "Not yet valid"

    else:
        validity_status = "Within validity period"

    # Deliberately exclude public PEM, raw certificate,
    # password, private key, salt and encrypted envelope.
    return {
        "fingerprint": key["fingerprint"],
        "subject_cn": certificate["subject_cn"],
        "valid_from": _format_certificate_time(
            certificate["not_before"]
        ),
        "expires_at": _format_certificate_time(
            expires_at
        ),
        "validity_status": validity_status,
        "is_currently_valid": (
            validity_status == "Within validity period"
        ),
    }


def _signing_error_page(user_id, message, status):
    """Render signing errors while retaining Task 2 information."""

    from user_keys import get_public_key

    try:
        encryption_key = get_public_key(user_id)

        return _render_keys(
            encryption_key,
            error=message,
            status=status,
        )

    except Exception:
        current_app.logger.error(
            "Unable to render signing key error page."
        )

        return _server_error()


@keys_bp.route(
    "/keys/signing/generate",
    methods=["POST"],
)
def generate_signing_keys():
    """Generate a signing keypair for the authenticated account."""

    from signing_keys import (
        generate_signing_keypair,
        get_signing_key,
    )

    user_id = current_user_id()

    if user_id is None:
        return redirect(url_for("login"))

    # Keep CSRF validation outside exception handling.
    # Invalid requests must abort before DB or crypto work.
    require_csrf()

    try:
        user = get_user_by_id(user_id)

        if user is None:
            session.clear()
            return redirect(url_for("login"))

        if get_signing_key(user_id) is not None:
            return _signing_error_page(
                user_id,
                _SIGNING_DUPLICATE_MESSAGE,
                409,
            )

    except Exception:
        current_app.logger.error(
            "Unable to check signing key generation eligibility."
        )
        return _server_error()

    # The authenticated session is authoritative.
    # Any user_id supplied in the form or URL is ignored.
    #
    # Do not strip or normalize the submitted password.
    password = request.form.get("password", "")

    if not password:
        return _signing_error_page(
            user_id,
            _SIGNING_PASSWORD_ERROR_MESSAGE,
            400,
        )

    try:
        generate_signing_keypair(
            user_id,
            password,
        )

    except KeyUnlockError:
        return _signing_error_page(
            user_id,
            _SIGNING_PASSWORD_ERROR_MESSAGE,
            400,
        )

    except ValueError:
        # A competing request may have generated the key
        # after the initial existence check.
        try:
            existing = get_signing_key(user_id)

        except Exception:
            current_app.logger.error(
                "Unable to recheck signing key existence."
            )
            return _server_error()

        if existing is not None:
            return _signing_error_page(
                user_id,
                _SIGNING_DUPLICATE_MESSAGE,
                409,
            )

        current_app.logger.error(
            "Signing key generation validation failed."
        )

        return _server_error()

    except Exception:
        # Do not expose exception messages, traceback,
        # password or cryptographic material.
        current_app.logger.error(
            "Signing key generation failed."
        )

        return _server_error()

    # The generation service has completed its transaction.
    # Only this successful request records key_generated.
    try:
        record_signature_event(
            user_id,
            None,
            "key_generated",
        )

    except Exception:
        # The signing key was already committed.
        # Do not delete it or retry generation.
        current_app.logger.error(
            "Signing key generated but audit recording failed."
        )

        return make_response(
            _SIGNING_AUDIT_ERROR_MESSAGE,
            503,
        )

    flash(
        _SIGNING_SUCCESS_MESSAGE,
        "keys-success",
    )

    return redirect(
        url_for("keys.my_keys"),
        code=303,
    )


@keys_bp.route(
    "/keys/signing/certificate",
    methods=["GET"],
)
def download_signing_certificate():
    """Download the current account's original certificate DER."""

    from signing_keys import get_signing_key
    from certificate import parse_certificate

    user_id = current_user_id()

    if user_id is None:
        return redirect(url_for("login"))

    try:
        user = get_user_by_id(user_id)

        if user is None:
            session.clear()
            return redirect(url_for("login"))

        # Never obtain the target user from request arguments.
        signing_key = get_signing_key(user_id)

        if signing_key is None:
            return make_response(
                "Signing certificate not found.",
                404,
            )

        certificate_der = signing_key["certificate_der"]

        if (
            not isinstance(certificate_der, bytes)
            or not certificate_der
        ):
            return _server_error()

        # Defensive structural check: do not accidentally
        # serve malformed or non-certificate key material.
        # No private key unlock or PKI trust verification.
        parse_certificate(certificate_der)

        # Normal Medimo usernames retain the contract's
        # medimo-<username>.cer naming convention.
        download_name = secure_filename(
            f"medimo-{user['username'][:80]}.cer"
        )

        if not download_name.endswith(".cer"):
            download_name = f"medimo-user-{user_id}.cer"

        response = send_file(
            io.BytesIO(certificate_der),
            mimetype=_CERTIFICATE_MIME_TYPE,
            as_attachment=True,
            download_name=download_name,
            conditional=False,
            etag=False,
            max_age=0,
        )

    except Exception:
        current_app.logger.error(
            "Unable to download signing certificate."
        )

        return _server_error()

    response.headers["X-Content-Type-Options"] = "nosniff"

    # The existing keys blueprint after_request handler
    # also applies Cache-Control: no-store.
    return response

@keys_bp.after_app_request
def _prevent_signing_route_error_caching(response):
    """Prevent caching even when routing rejects the request."""

    if request.path in (
        "/keys/signing/generate",
        "/keys/signing/certificate",
    ):
        response.headers["Cache-Control"] = "no-store"

    return response