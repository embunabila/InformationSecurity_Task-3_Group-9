"""Medimo RSA signing, verification and signing-key management."""

import hmac
import re
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

from crypto_core import (
    encrypt_blob,
    decrypt_blob,
    InvalidEnvelopeError,
)
from db import get_connection
from share_errors import (
    KeyUnlockError,
    KeyLockedError,
    InvalidSignatureError,
    UnsupportedSignatureError,
)

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

    if user_id > (1 << 63) - 1:
        raise ValueError("User does not exist.")

    if not isinstance(password, str) or not password:
        raise KeyUnlockError("Password verification failed.")

    # Phase 1: Account and duplicate validation.

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

    # Phase 2: Generate key material without a database write lock.

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
        del private_key

    created_at = not_before.isoformat()
    expires_at = not_after.isoformat()

    # Phase 3: Atomic database persistence.

    with closing(get_connection()) as connection:
        try:
            with connection:
                connection.execute("BEGIN IMMEDIATE")

                if _signing_key_exists(connection, user_id):
                    raise ValueError(
                        "User already has a signing keypair."
                    )

                current_user = _read_signing_account(
                    connection,
                    user_id,
                )

                if (
                    current_user is None
                    or current_user["password_hash"] != password_hash
                ):
                    raise KeyUnlockError(
                        "Password verification failed."
                    )

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
            if (
                getattr(exc, "sqlite_errorcode", None)
                == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
            ):
                raise ValueError(
                    "User already has a signing keypair."
                ) from None

            raise


# ============================================================
# Stage 5c: Public signing-key retrieval and signer lookup
# ============================================================

_SIGNING_FINGERPRINT_PATTERN = re.compile(
    r"[0-9A-F]{4}( [0-9A-F]{4}){15}"
)


def get_signing_key(user_id) -> dict | None:
    """Return public signing-key information, if available."""

    _signing_key_context(user_id)

    if user_id > (1 << 63) - 1:
        raise ValueError("User does not exist.")

    with closing(get_connection()) as connection:
        row = connection.execute(
            """
            SELECT
                public_key_pem,
                fingerprint,
                certificate_der,
                expires_at
            FROM signing_keys
            WHERE user_id = ?
            """,
            (user_id,),
        ).fetchone()

    if row is None:
        return None

    return {
        "public_key_pem": row["public_key_pem"],
        "fingerprint": row["fingerprint"],
        "certificate_der": row["certificate_der"],
        "expires_at": row["expires_at"],
    }


def find_signer_by_fingerprint(fingerprint) -> dict | None:
    """Resolve a canonical signing fingerprint to a registered user."""

    if (
        not isinstance(fingerprint, str)
        or len(fingerprint) != 79
        or _SIGNING_FINGERPRINT_PATTERN.fullmatch(
            fingerprint
        ) is None
    ):
        raise ValueError("Invalid signing fingerprint.")

    with closing(get_connection()) as connection:
        row = connection.execute(
            """
            SELECT
                sk.user_id,
                u.username
            FROM signing_keys AS sk
            JOIN users AS u
                ON u.id = sk.user_id
            WHERE sk.fingerprint = ?
            """,
            (fingerprint,),
        ).fetchone()

    if row is None:
        return None

    return {
        "user_id": row["user_id"],
        "username": row["username"],
    }


# ============================================================
# Stage 6: Signing-key unlock and security
# ============================================================

_SIGNING_MAX_FAILED_ATTEMPTS = 5
_SIGNING_LOCKOUT_MINUTES = 15

_SIGNING_UNLOCK_MESSAGE = (
    "Private signing key could not be verified."
)

_SIGNING_LOCKED_MESSAGE = (
    "Too many signing key unlock attempts."
)

_SIGNING_MATERIAL_FIELDS = (
    "public_key_pem",
    "fingerprint",
    "certificate_der",
    "private_key_salt",
    "encrypted_private_key",
    "expires_at",
    "created_at",
)


def _read_signing_unlock_state(connection, user_id):
    """Read signing key material and its independent lockout state."""

    return connection.execute(
        """
        SELECT
            public_key_pem,
            fingerprint,
            certificate_der,
            private_key_salt,
            encrypted_private_key,
            expires_at,
            created_at,
            failed_unlock_count,
            locked_until
        FROM signing_keys
        WHERE user_id = ?
        """,
        (user_id,),
    ).fetchone()


def _parse_signing_timestamp(value):
    """Parse a timezone-aware UTC timestamp from signing_keys."""

    if not isinstance(value, str):
        raise ValueError("Expected UTC timestamp")

    result = datetime.fromisoformat(value)

    if (
        result.tzinfo is None
        or result.utcoffset() != timedelta(0)
    ):
        raise ValueError(
            "Expected timezone-aware UTC timestamp"
        )

    return result.astimezone(timezone.utc)


def _update_signing_unlock_state(
    connection,
    user_id,
    count,
    locked_until,
):
    """Update only the signing key's security state."""

    cursor = connection.execute(
        """
        UPDATE signing_keys
        SET
            failed_unlock_count = ?,
            locked_until = ?
        WHERE user_id = ?
        """,
        (
            count,
            locked_until,
            user_id,
        ),
    )

    if cursor.rowcount != 1:
        raise RuntimeError(
            "Signing key security state was not updated."
        )


def _check_signing_unlock_state(
    connection,
    user_id,
    row,
    now,
):
    """Reject active lockouts and reset expired lockouts."""

    count = row["failed_unlock_count"]

    try:
        if (
            type(count) is not int
            or not 0 <= count <= _SIGNING_MAX_FAILED_ATTEMPTS
        ):
            raise ValueError(
                "Invalid failed unlock count"
            )

        locked_until = (
            None
            if row["locked_until"] is None
            else _parse_signing_timestamp(
                row["locked_until"]
            )
        )

        # Fail closed if the stored counter indicates a lockout
        # but the required expiry timestamp is missing.
        if (
            locked_until is None
            and count == _SIGNING_MAX_FAILED_ATTEMPTS
        ):
            raise ValueError(
                "Missing lockout timestamp"
            )

    except (ValueError, OverflowError):
        raise KeyUnlockError(
            _SIGNING_UNLOCK_MESSAGE
        ) from None

    if locked_until is not None:
        if now < locked_until:
            raise KeyLockedError(
                _SIGNING_LOCKED_MESSAGE
            )

        # The previous lockout has expired.
        _update_signing_unlock_state(
            connection,
            user_id,
            0,
            None,
        )

        return 0

    return count


def _same_signing_key_material(first, second):
    """Detect replacement of any stored signing key material."""

    return all(
        first[field] == second[field]
        for field in _SIGNING_MATERIAL_FIELDS
    )


def _recover_signing_private_key(
    user_id,
    password,
    row,
):
    """Recover and validate an authenticated RSA-3072 signing key."""

    if (
        not isinstance(password, str)
        or not password
    ):
        raise KeyUnlockError(
            _SIGNING_UNLOCK_MESSAGE
        )

    salt = row["private_key_salt"]
    envelope = row["encrypted_private_key"]

    if (
        not isinstance(salt, bytes)
        or len(salt) != _SIGNING_KEK_SALT_SIZE
        or not isinstance(envelope, bytes)
    ):
        raise KeyUnlockError(
            _SIGNING_UNLOCK_MESSAGE
        )

    # Distinguish malformed password input from unexpected
    # internal failures during the actual KDF operation.
    try:
        password.encode("utf-8")

    except UnicodeError:
        raise KeyUnlockError(
            _SIGNING_UNLOCK_MESSAGE
        ) from None

    kek = _derive_signing_kek(
        password,
        salt,
    )

    try:
        private_der = decrypt_blob(
            envelope,
            kek,
            "AES",
            _signing_key_context(user_id),
        )

    except InvalidEnvelopeError:
        raise KeyUnlockError(
            _SIGNING_UNLOCK_MESSAGE
        ) from None

    finally:
        # Release the reference, not guaranteed zeroization.
        del kek

    # ========================================================
    # Validate recovered private key
    # ========================================================

    try:
        fields = decode_value(
            validate_tree(
                parse_der(private_der)
            ),
            0x30,
        )

        # Generation stores PKCS#8 PrivateKeyInfo:
        # SEQUENCE {
        #     version INTEGER,
        #     privateKeyAlgorithm AlgorithmIdentifier,
        #     privateKey OCTET STRING
        # }
        if (
            tuple(field.tag for field in fields)
            != (0x02, 0x30, 0x04)
            or decode_value(fields[0], 0x02) != 0
        ):
            raise ValueError(
                "Expected PKCS#8 PrivateKeyInfo"
            )

        key = RSA.import_key(
            private_der
        )

        if (
            not isinstance(key, RSA.RsaKey)
            or not key.has_private()
            or key.size_in_bits() != _MEDIMO_SIGNING_BITS
        ):
            raise ValueError(
                "Expected RSA-3072 private key"
            )

        # Do not rely solely on successful key import.
        # Explicitly check the RSA private components.
        key = RSA.construct(
            (
                key.n,
                key.e,
                key.d,
                key.p,
                key.q,
                key.u,
            ),
            consistency_check=True,
        )

        _validate_signing_public_key(
            key.public_key()
        )

    except (
        ValueError,
        TypeError,
        IndexError,
        OverflowError,
    ):
        raise KeyUnlockError(
            _SIGNING_UNLOCK_MESSAGE
        ) from None

    finally:
        del private_der

    # ========================================================
    # Validate stored public key and fingerprint
    # ========================================================

    try:
        stored_pem = row["public_key_pem"]

        if (
            not isinstance(stored_pem, str)
            or not stored_pem.startswith(
                "-----BEGIN PUBLIC KEY-----"
            )
        ):
            raise ValueError(
                "Invalid stored public PEM"
            )

        stored_fingerprint = (
            signing_public_key_fingerprint(
                stored_pem
            )
        )

        recovered_fingerprint = (
            signing_public_key_fingerprint(
                key.public_key().export_key(
                    format="DER"
                )
            )
        )

        stored_key = _validate_signing_public_key(
            RSA.import_key(stored_pem)
        )

        if (
            (key.n, key.e)
            != (stored_key.n, stored_key.e)
        ):
            raise ValueError(
                "Stored public key mismatch"
            )

        if (
            recovered_fingerprint != row["fingerprint"]
            or stored_fingerprint != row["fingerprint"]
        ):
            raise ValueError(
                "Stored fingerprint mismatch"
            )

        # ====================================================
        # Validate stored Medimo certificate
        # ====================================================

        certificate = parse_certificate(
            row["certificate_der"]
        )

        certificate_key = _validate_signing_public_key(
            RSA.import_key(
                certificate["public_key_pem"]
            )
        )

        if (
            (certificate_key.n, certificate_key.e)
            != (key.n, key.e)
        ):
            raise ValueError(
                "Stored certificate public key mismatch"
            )

        certificate_fingerprint = (
            signing_public_key_fingerprint(
                certificate["public_key_pem"]
            )
        )

        if certificate_fingerprint != recovered_fingerprint:
            raise ValueError(
                "Stored certificate fingerprint mismatch"
            )

        # Unlike external certificates, the stored Medimo
        # certificate must follow the self-issued v3 profile.
        #
        # The certificate parser already validates the complete
        # TBS structure, so use its original DER for comparison.
        tbs = decode_value(
            parse_der(
                certificate["tbs_der"]
            ),
            0x30,
        )

        if (
            len(tbs) < 7
            or tbs[0].raw != b"\xa0\x03\x02\x01\x02"
            or tbs[3].raw != tbs[5].raw
        ):
            raise ValueError(
                "Expected self-issued X.509 v3 certificate"
            )

        if not rsa_verify(
            certificate["public_key_pem"],
            certificate["tbs_der"],
            certificate["signature"],
        ):
            raise ValueError(
                "Stored certificate self-signature mismatch"
            )

        # Validate metadata, but do not enforce the current
        # certificate expiry policy here.
        if (
            certificate["not_after"]
            != _parse_signing_timestamp(
                row["expires_at"]
            )
            or certificate["not_before"]
            != _parse_signing_timestamp(
                row["created_at"]
            )
            or certificate["not_after"]
            - certificate["not_before"]
            != timedelta(
                days=_SIGNING_VALIDITY_DAYS
            )
        ):
            raise ValueError(
                "Stored certificate validity mismatch"
            )

    except (
        ValueError,
        TypeError,
        IndexError,
        OverflowError,
        InvalidSignatureError,
        UnsupportedSignatureError,
    ):
        raise KeyUnlockError(
            _SIGNING_UNLOCK_MESSAGE
        ) from None

    return key


def unlock_signing_key(
    user_id,
    password,
) -> RSA.RsaKey:
    """Unlock an RSA signing key with atomic lockout protection."""

    _signing_key_context(user_id)

    if user_id > (1 << 63) - 1:
        raise ValueError(
            "User does not exist."
        )

    # ========================================================
    # Phase 1: Read and check the current security state
    # ========================================================

    with closing(get_connection()) as connection:
        with connection:
            connection.execute(
                "BEGIN IMMEDIATE"
            )

            snapshot = _read_signing_unlock_state(
                connection,
                user_id,
            )

            if snapshot is None:
                raise KeyUnlockError(
                    _SIGNING_UNLOCK_MESSAGE
                )

            _check_signing_unlock_state(
                connection,
                user_id,
                snapshot,
                _signing_utc_now(),
            )

    # ========================================================
    # Phase 2: Expensive recovery outside the DB write lock
    # ========================================================

    private_key = None

    try:
        private_key = _recover_signing_private_key(
            user_id,
            password,
            snapshot,
        )

    except KeyUnlockError:
        # Expected recovery failures must be counted atomically
        # against the latest state in the final transaction.
        pass

    # ========================================================
    # Phase 3: Recheck and finalize the security state
    # ========================================================

    result_error = None

    try:
        with closing(get_connection()) as connection:
            with connection:
                connection.execute(
                    "BEGIN IMMEDIATE"
                )

                current = _read_signing_unlock_state(
                    connection,
                    user_id,
                )

                # Do not update a newly substituted or deleted key.
                if (
                    current is None
                    or not _same_signing_key_material(
                        snapshot,
                        current,
                    )
                ):
                    raise KeyUnlockError(
                        _SIGNING_UNLOCK_MESSAGE
                    )

                now = _signing_utc_now()

                # A concurrent failed attempt may have established
                # a lockout while recovery was in progress.
                count = _check_signing_unlock_state(
                    connection,
                    user_id,
                    current,
                    now,
                )

                if private_key is None:
                    count = min(
                        count + 1,
                        _SIGNING_MAX_FAILED_ATTEMPTS,
                    )

                    if count == _SIGNING_MAX_FAILED_ATTEMPTS:
                        locked_until = now + timedelta(
                            minutes=_SIGNING_LOCKOUT_MINUTES
                        )

                        _update_signing_unlock_state(
                            connection,
                            user_id,
                            count,
                            locked_until.isoformat(),
                        )

                        result_error = KeyLockedError(
                            _SIGNING_LOCKED_MESSAGE
                        )

                    else:
                        _update_signing_unlock_state(
                            connection,
                            user_id,
                            count,
                            None,
                        )

                        result_error = KeyUnlockError(
                            _SIGNING_UNLOCK_MESSAGE
                        )

                else:
                    # Only a validated recovery may reset the
                    # latest unlocked security state.
                    _update_signing_unlock_state(
                        connection,
                        user_id,
                        0,
                        None,
                    )

    except BaseException:
        # Never return a recovered key after a database,
        # concurrency, lockout or transaction failure.
        del private_key
        raise

    # Authentication errors must be raised AFTER the state
    # update commits, otherwise SQLite rolls back the counter.
    if result_error is not None:
        raise result_error

    return private_key
