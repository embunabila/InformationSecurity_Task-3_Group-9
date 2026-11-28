"""Internal EMSA-PKCS1-v1_5 encoding for Medimo signing keys."""

import hmac

from Crypto.Hash import SHA256
from Crypto.IO import PEM
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from der import decode_value, parse_der, validate_tree


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
        raise ValueError(
            "Invalid encoded message length"
        )

    if type(include_null) is not bool:
        raise ValueError(
            "include_null must be bool"
        )

    prefix = (
        _SHA256_DIGESTINFO_NULL
        if include_null
        else _SHA256_DIGESTINFO_ABSENT
    )

    digest_info = prefix + digest

    padding_len = em_len - len(digest_info) - 3

    if padding_len < _MIN_PADDING_SIZE:
        raise ValueError(
            "Encoded message length is too short"
        )

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
        raise ValueError(
            "An RSA private key is required"
        )

    try:
        n = private_key.n
        e = private_key.e
        d = private_key.d

    except (
        AttributeError,
        TypeError,
        ValueError,
    ) as exc:
        raise ValueError(
            "Invalid RSA private key"
        ) from exc

    if n.bit_length() != _MEDIMO_SIGNING_BITS:
        raise ValueError(
            "Medimo signing requires an RSA-3072 key"
        )

    if not 3 <= e < n or e % 2 == 0 or not 1 < d < n:
        raise ValueError(
            "Invalid RSA private key"
        )

    # Reject inconsistent RsaKey objects, including keys
    # constructed with consistency_check=False.
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

    except (
        AttributeError,
        TypeError,
        ValueError,
    ) as exc:
        raise ValueError(
            "Invalid RSA private key"
        ) from exc

    k = (n.bit_length() + 7) // 8

    em = _emsa_pkcs1_v1_5_encode(
        message,
        k,
        include_null=True,
    )

    m = int.from_bytes(em, "big")

    if not 0 <= m < n:
        raise ValueError(
            "Message representative out of range"
        )

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
        raise ValueError(
            "An RSA public key is required"
        )

    n, e = public_key.n, public_key.e

    if n <= 0 or n % 2 == 0:
        raise ValueError(
            "Invalid RSA modulus"
        )

    if not _MIN_VERIFY_BITS <= n.bit_length() <= _MAX_VERIFY_BITS:
        raise ValueError(
            "Unsupported RSA modulus size"
        )

    if not 3 <= e < n or e % 2 == 0:
        raise ValueError(
            "Invalid RSA public exponent"
        )

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

        # The contract takes public-key PEM, not certificates,
        # DER or private keys.
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
        raise ValueError(
            "Public key must be PEM or DER"
        )

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
                raise ValueError(
                    "Expected public-key PEM"
                )

        elif isinstance(public_key, str):
            raise ValueError(
                "Text public key must be PEM"
            )

        # Accept bare PKCS#1 or SubjectPublicKeyInfo,
        # not certificates or private-key containers
        # accepted by RSA.import_key itself.
        fields = decode_value(
            validate_tree(parse_der(raw)),
            0x30,
        )

        tags = tuple(field.tag for field in fields)

        # Normalize marker returned by the PEM decoder.
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
            

        if tuple(
            field.tag for field in fields
        ) not in (
            (0x02, 0x02),
            (0x30, 0x03),
        ):
            raise ValueError(
                "Expected DER public key"
            )

        key = _validate_signing_public_key(
            RSA.import_key(raw)
        )

        canonical_der = key.export_key(
            format="DER"
        )

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