"""Medimo RSA signing, verification and signing-key management."""

import hmac
import sqlite3

from contextlib import closing
from datetime import datetime, timedelta, timezone

from Crypto.Hash import SHA256
from Crypto.IO import PEM
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from werkzeug.security import check_password_hash

from certificate import (
    build_self_signed_certificate,
    parse_certificate,
)

from crypto_core import encrypt_blob
from db import get_connection
from share_errors import KeyUnlockError

from der import (
    decode_value,
    parse_der,
    validate_tree,
)


# ============================================================
# Stage 3a: EMSA-PKCS1-v1_5 encoding
# ============================================================

_SHA256_DIGEST_SIZE = 32

_SHA256_DIGESTINFO_NULL = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)

_SHA256_DIGESTINFO_ABSENT = bytes.fromhex(
    "302f300b06096086480165030402010420"
)

_MIN_PADDING_SIZE = 8
_MAX_EM_LENGTH = 512


def _emsa_pkcs1_v1_5_encode_digest(
    digest, em_len, *, include_null=True
):
    """Build a fixed-length encoded message from a SHA-256 digest."""

    if (
        not isinstance(digest, bytes)
        or len(digest) != _SHA256_DIGEST_SIZE
    ):
        raise ValueError(
            "SHA-256 digest must be exactly 32 bytes"
        )

    if (
        type(em_len) is not int
        or not 1 <= em_len <= _MAX_EM_LENGTH
    ):
        raise ValueError("Invalid encoded message length")

    if type(include_null) is not bool:
        raise ValueError("include_null must be bool")

    prefix = (
        _SHA256_DIGESTINFO_NULL
        if include_null
        else _SHA256_DIGESTINFO_ABSENT
    )

    digest_info = prefix + digest
    padding_len = em_len - len(digest_info) - 3

    if padding_len < _MIN_PADDING_SIZE:
        raise ValueError("Encoded message length is too short")

    return (
        b"\x00\x01"
        + b"\xff" * padding_len
        + b"\x00"
        + digest_info
    )


def _emsa_pkcs1_v1_5_encode(
    message, em_len, *, include_null=True
):
    """Hash message bytes and encode them using EMSA-PKCS1-v1_5."""

    if not isinstance(message, bytes):
        raise ValueError("Message must be bytes")

    return _emsa_pkcs1_v1_5_encode_digest(
        SHA256.new(message).digest(),
        em_len,
        include_null=include_null,
    )


# ============================================================
# Stage 3b: RSA signing
# ============================================================

_MEDIMO_SIGNING_BITS = 3072


def rsa_sign(private_key, message) -> bytes:
    """Sign message bytes using Medimo's RSA-3072 and SHA-256 policy."""

    if not isinstance(message, bytes):
        raise ValueError("Message must be bytes")

    if (
        not isinstance(private_key, RSA.RsaKey)
        or not private_key.has_private()
    ):
        raise ValueError("An RSA private key is required")

    try:
        n = private_key.n
        e = private_key.e
        d = private_key.d

    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("Invalid RSA private key") from exc

    if n.bit_length() != _MEDIMO_SIGNING_BITS:
        raise ValueError(
            "Medimo signing requires an RSA-3072 key"
        )

    if not 3 <= e < n or e % 2 == 0 or not 1 < d < n:
        raise ValueError("Invalid RSA private key")

    try:
        RSA.construct(
            (
                n,
                e,
                d,
                private_key.p,
                private_key.q,
                private_key.u,
            ),
            consistency_check=True,
        )

    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("Invalid RSA private key") from exc

    k = (n.bit_length() + 7) // 8

    em = _emsa_pkcs1_v1_5_encode(
        message,
        k,
        include_null=True,
    )

    m = int.from_bytes(em, "big")

    if not 0 <= m < n:
        raise ValueError("Message representative out of range")

    s = pow(m, d, n)

    return s.to_bytes(k, "big")


# ============================================================
# Shared RSA public-key validation
# ============================================================

_MIN_VERIFY_BITS = 2048
_MAX_VERIFY_BITS = 4096


def _validate_signing_public_key(public_key):
    """Validate public RSA components under the verification policy."""

    if (
        not isinstance(public_key, RSA.RsaKey)
        or public_key.has_private()
    ):
        raise ValueError("An RSA public key is required")

    n, e = public_key.n, public_key.e

    if n <= 0 or n % 2 == 0:
        raise ValueError("Invalid RSA modulus")

    if not _MIN_VERIFY_BITS <= n.bit_length() <= _MAX_VERIFY_BITS:
        raise ValueError("Unsupported RSA modulus size")

    if not 3 <= e < n or e % 2 == 0:
        raise ValueError("Invalid RSA public exponent")

    return RSA.construct(
        (n, e),
        consistency_check=True,
    )


# ============================================================
# Stage 3c: RSA verification
# ============================================================


def rsa_verify(public_key_pem, message, signature) -> bool:
    """Verify RSA/SHA-256 signatures under the Medimo verification profile."""

    if not isinstance(public_key_pem, (bytes, str)):
        return False

    if (
        not isinstance(message, bytes)
        or not isinstance(signature, bytes)
    ):
        return False

    try:
        pem = (
            public_key_pem.encode("ascii")
            if isinstance(public_key_pem, str)
            else public_key_pem
        ).strip()

        if not pem.startswith((
            b"-----BEGIN PUBLIC KEY-----",
            b"-----BEGIN RSA PUBLIC KEY-----",
        )):
            return False

        public_key = RSA.import_key(pem)

        public_key = _validate_signing_public_key(
            public_key
        )

        n, e = public_key.n, public_key.e

    except (
        ValueError,
        TypeError,
        IndexError,
        OverflowError,
        AttributeError,
    ):
        return False

    k = (n.bit_length() + 7) // 8

    if len(signature) != k:
        return False

    s = int.from_bytes(signature, "big")

    if not 0 <= s < n:
        return False

    m = pow(s, e, n)
    recovered_em = m.to_bytes(k, "big")

    digest = SHA256.new(message).digest()

    expected_null = _emsa_pkcs1_v1_5_encode_digest(
        digest,
        k,
        include_null=True,
    )

    expected_absent = _emsa_pkcs1_v1_5_encode_digest(
        digest,
        k,
        include_null=False,
    )

    matches_null = hmac.compare_digest(
        recovered_em,
        expected_null,
    )

    matches_absent = hmac.compare_digest(
        recovered_em,
        expected_absent,
    )

    return matches_null | matches_absent


# ============================================================
# Stage 5a: Signing-key management helpers
# ============================================================

_SIGNING_KEK_SIZE = 32
_SIGNING_KEK_SALT_SIZE = 16

_SIGNING_SCRYPT_N = 2**17
_SIGNING_SCRYPT_R = 8
_SIGNING_SCRYPT_P = 1


def signing_public_key_fingerprint(public_key) -> str:
    """Fingerprint a serialized RSA public key (PEM or DER)."""

    if not isinstance(public_key, (bytes, str)):
        raise ValueError("Public key must be PEM or DER")

    try:
        raw = (
            public_key.encode("ascii")
            if isinstance(public_key, str)
            else public_key
        )

        # Required for raw DER inputs.
        marker = None

        if raw.lstrip().startswith(b"-----BEGIN "):
            raw, marker, encrypted = PEM.decode(
                raw.decode("ascii").strip()
            )

            if encrypted or marker not in (
                "PUBLIC KEY",
                "RSA PUBLIC KEY",
            ):
                raise ValueError("Expected public-key PEM")

        elif isinstance(public_key, str):
            raise ValueError("Text public key must be PEM")

        fields = decode_value(
            validate_tree(parse_der(raw)),
            0x30,
        )

        tags = tuple(field.tag for field in fields)

        if isinstance(marker, bytes):
            marker = marker.decode("ascii")

        if marker in (
            "PUBLIC KEY",
            "-----BEGIN PUBLIC KEY-----",
        ):
            if tags != (0x30, 0x03):
                raise ValueError(
                    "PEM label does not match SPKI structure"
                )

        elif marker in (
            "RSA PUBLIC KEY",
            "-----BEGIN RSA PUBLIC KEY-----",
        ):
            if tags != (0x02, 0x02):
                raise ValueError(
                    "PEM label does not match PKCS#1 structure"
                )

        if tags not in (
            (0x02, 0x02),
            (0x30, 0x03),
        ):
            raise ValueError("Expected DER public key")

        key = _validate_signing_public_key(
            RSA.import_key(raw)
        )

        canonical_der = key.export_key(format="DER")

    except (
        ValueError,
        TypeError,
        IndexError,
        OverflowError,
        AttributeError,
    ) as exc:
        raise ValueError(
            "Invalid or unsupported RSA public key"
        ) from exc

    digest = SHA256.new(
        canonical_der
    ).hexdigest().upper()

    return " ".join(
        digest[i:i + 4]
        for i in range(0, len(digest), 4)
    )


def _generate_signing_kek_salt() -> bytes:
    """Generate a fresh signing-key KEK salt."""

    return get_random_bytes(
        _SIGNING_KEK_SALT_SIZE
    )


def _derive_signing_kek(
    password: str,
    salt: bytes,
) -> bytes:
    """Derive a 32-byte KEK using the Task 3 scrypt profile."""

    if (
        not isinstance(password, str)
        or not password
    ):
        raise ValueError(
            "Password must be a non-empty string"
        )

    if (
        not isinstance(salt, bytes)
        or len(salt) != _SIGNING_KEK_SALT_SIZE
    ):
        raise ValueError(
            "KEK salt must be exactly 16 bytes"
        )

    return scrypt(
        password.encode("utf-8"),
        salt,
        key_len=_SIGNING_KEK_SIZE,
        N=_SIGNING_SCRYPT_N,
        r=_SIGNING_SCRYPT_R,
        p=_SIGNING_SCRYPT_P,
    )


def _signing_key_context(user_id: int) -> dict:
    """Build the authenticated context used for signing keys."""

    if (
        isinstance(user_id, bool)
        or not isinstance(user_id, int)
        or user_id <= 0
    ):
        raise ValueError(
            "User ID must be a positive integer"
        )

    return {
        "owner_id": user_id,
        "kind": "signing_key",
        "item_id": "signing_key",
    }


# ============================================================
# Stage 5b: Signing-key generation
# ============================================================

_SIGNING_VALIDITY_DAYS = 730


def _signing_utc_now() -> datetime:
    """Return the current timezone-aware UTC time."""

    return datetime.now(timezone.utc)


def _read_signing_account(connection, user_id):
    """Read account information needed for signing-key generation."""

    return connection.execute(
        """
        SELECT username, password_hash
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()


def _signing_key_exists(connection, user_id) -> bool:
    """Check whether the user already has a signing keypair."""

    return connection.execute(
        """
        SELECT 1
        FROM signing_keys
        WHERE user_id = ?
        """,
        (user_id,),
    ).fetchone() is not None


def _validate_generated_certificate(
    certificate_der,
    private_key,
    fingerprint,
    username,
    not_before,
    not_after,
):
    """Check a newly generated Medimo certificate before persistence."""

    parsed = parse_certificate(certificate_der)

    certificate_key = RSA.import_key(
        parsed["public_key_pem"]
    )

    certificate_key = _validate_signing_public_key(
        certificate_key
    )

    # Match the certificate against the actual generated key.
    if (
        certificate_key.n != private_key.n
        or certificate_key.e != private_key.e
        or certificate_key.size_in_bits() != _MEDIMO_SIGNING_BITS
    ):
        raise RuntimeError(
            "Generated certificate public key mismatch."
        )

    certificate_fingerprint = signing_public_key_fingerprint(
        parsed["public_key_pem"]
    )

    if certificate_fingerprint != fingerprint:
        raise RuntimeError(
            "Generated certificate fingerprint mismatch."
        )

    if parsed["subject_cn"] != username:
        raise RuntimeError(
            "Generated certificate subject mismatch."
        )

    if (
        parsed["not_before"] != not_before
        or parsed["not_after"] != not_after
    ):
        raise RuntimeError(
            "Generated certificate validity mismatch."
        )

    if not rsa_verify(
        parsed["public_key_pem"],
        parsed["tbs_der"],
        parsed["signature"],
    ):
        raise RuntimeError(
            "Generated certificate self-signature is invalid."
        )


def generate_signing_keypair(user_id, password) -> None:
    """Generate and securely store a user's independent RSA signing keypair."""

    context = _signing_key_context(user_id)

    # SQLite INTEGER PRIMARY KEY uses signed 64-bit integers.
    if user_id > (1 << 63) - 1:
        raise ValueError("User does not exist.")

    if not isinstance(password, str) or not password:
        raise KeyUnlockError("Password verification failed.")

    # ========================================================
    # Phase 1: Account and duplicate validation
    # ========================================================

    with closing(get_connection()) as connection:
        user = _read_signing_account(
            connection,
            user_id,
        )

        if user is None:
            raise ValueError("User does not exist.")

        if _signing_key_exists(connection, user_id):
            raise ValueError(
                "User already has a signing keypair."
            )

    username = user["username"]
    password_hash = user["password_hash"]

    try:
        password_valid = check_password_hash(
            password_hash,
            password,
        )

    except UnicodeError:
        raise KeyUnlockError(
            "Password verification failed."
        ) from None

    if not password_valid:
        raise KeyUnlockError(
            "Password verification failed."
        )

    # ========================================================
    # Phase 2: Generate all key material without a DB write lock
    # ========================================================

    private_key = RSA.generate(
        _MEDIMO_SIGNING_BITS
    )

    try:
        public_key_pem = (
            private_key.public_key()
            .export_key(format="PEM")
            .decode("ascii")
        )

        fingerprint = signing_public_key_fingerprint(
            public_key_pem
        )

        salt = _generate_signing_kek_salt()

        kek = _derive_signing_kek(
            password,
            salt,
        )

        try:
            private_der = private_key.export_key(
                format="DER",
                pkcs=8,
            )

            try:
                encrypted_private_key = encrypt_blob(
                    private_der,
                    kek,
                    "AES",
                    context,
                )

            finally:
                del private_der

        finally:
            del kek

        # Use one UTC timestamp, truncated to whole seconds.
        not_before = _signing_utc_now().replace(
            microsecond=0
        )

        not_after = not_before + timedelta(
            days=_SIGNING_VALIDITY_DAYS
        )

        certificate_der = build_self_signed_certificate(
            private_key,
            username,
            not_before,
            not_after,
        )

        _validate_generated_certificate(
            certificate_der,
            private_key,
            fingerprint,
            username,
            not_before,
            not_after,
        )

    finally:
        # Release references, not a guarantee of secure zeroization.
        del private_key

    created_at = not_before.isoformat()
    expires_at = not_after.isoformat()

    # ========================================================
    # Phase 3: Atomic database persistence
    # ========================================================

    with closing(get_connection()) as connection:
        try:
            with connection:
                connection.execute("BEGIN IMMEDIATE")

                # A concurrent request may have generated a key
                # while this request was performing RSA or scrypt.
                if _signing_key_exists(connection, user_id):
                    raise ValueError(
                        "User already has a signing keypair."
                    )

                current_user = _read_signing_account(
                    connection,
                    user_id,
                )

                # Reject stale credentials or a deleted account.
                if (
                    current_user is None
                    or current_user["password_hash"] != password_hash
                ):
                    raise KeyUnlockError(
                        "Password verification failed."
                    )

                # CN must still match the account used to build
                # the certificate.
                if current_user["username"] != username:
                    raise RuntimeError(
                        "Account username changed during key generation."
                    )

                connection.execute(
                    """
                    INSERT INTO signing_keys (
                        user_id,
                        public_key_pem,
                        fingerprint,
                        certificate_der,
                        private_key_salt,
                        encrypted_private_key,
                        failed_unlock_count,
                        locked_until,
                        expires_at,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, 0, NULL, ?, ?)
                    """,
                    (
                        user_id,
                        public_key_pem,
                        fingerprint,
                        certificate_der,
                        salt,
                        encrypted_private_key,
                        expires_at,
                        created_at,
                    ),
                )

        except sqlite3.IntegrityError as exc:
            # Only the primary-key violation is treated as a
            # duplicate user signing key.
            if (
                getattr(exc, "sqlite_errorcode", None)
                == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
            ):
                raise ValueError(
                    "User already has a signing keypair."
                ) from None

            # Other database failures must remain visible.
            raise