"""Internal EMSA-PKCS1-v1_5 encoding for Medimo signing keys."""

import hmac

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


_SHA256_DIGEST_SIZE = 32
_SHA256_DIGESTINFO_NULL = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)
_SHA256_DIGESTINFO_ABSENT = bytes.fromhex(
    "302f300b06096086480165030402010420"
)
_MIN_PADDING_SIZE = 8
_MAX_EM_LENGTH = 512  # Medimo supports RSA up to 4096 bits.


def _emsa_pkcs1_v1_5_encode_digest(digest, em_len, *, include_null=True):
    """Build a fixed-length encoded message from a SHA-256 digest."""
    if not isinstance(digest, bytes) or len(digest) != _SHA256_DIGEST_SIZE:
        raise ValueError("SHA-256 digest must be exactly 32 bytes")

    if type(em_len) is not int or not 1 <= em_len <= _MAX_EM_LENGTH:
        raise ValueError("Invalid encoded message length")

    if type(include_null) is not bool:
        raise ValueError("include_null must be bool")

    prefix = (
        _SHA256_DIGESTINFO_NULL if include_null
        else _SHA256_DIGESTINFO_ABSENT
    )
    digest_info = prefix + digest
    padding_len = em_len - len(digest_info) - 3

    if padding_len < _MIN_PADDING_SIZE:
        raise ValueError("Encoded message length is too short")

    return b"\x00\x01" + b"\xff" * padding_len + b"\x00" + digest_info


def _emsa_pkcs1_v1_5_encode(message, em_len, *, include_null=True):
    """Hash message bytes and encode them using EMSA-PKCS1-v1_5."""
    if not isinstance(message, bytes):
        raise ValueError("Message must be bytes")

    return _emsa_pkcs1_v1_5_encode_digest(
        SHA256.new(message).digest(), em_len, include_null=include_null
    )


_MEDIMO_SIGNING_BITS = 3072


def rsa_sign(private_key, message) -> bytes:
    """Sign message bytes using Medimo's RSA-3072 and SHA-256 policy."""
    if not isinstance(message, bytes):
        raise ValueError("Message must be bytes")

    if not isinstance(private_key, RSA.RsaKey) or not private_key.has_private():
        raise ValueError("An RSA private key is required")

    try:
        n = private_key.n
        e = private_key.e
        d = private_key.d
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("Invalid RSA private key") from exc

    if n.bit_length() != _MEDIMO_SIGNING_BITS:
        raise ValueError("Medimo signing requires an RSA-3072 key")

    if not 3 <= e < n or e % 2 == 0 or not 1 < d < n:
        raise ValueError("Invalid RSA private key")

    # Reject inconsistent RsaKey objects, including keys constructed
    # with consistency_check=False. This is key validation only.
    try:
        RSA.construct(
            (n, e, d, private_key.p, private_key.q, private_key.u),
            consistency_check=True,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("Invalid RSA private key") from exc

    k = (n.bit_length() + 7) // 8
    em = _emsa_pkcs1_v1_5_encode(message, k, include_null=True)
    m = int.from_bytes(em, "big")

    if not 0 <= m < n:
        raise ValueError("Message representative out of range")

    s = pow(m, d, n)
    return s.to_bytes(k, "big")


_MIN_VERIFY_BITS = 2048
_MAX_VERIFY_BITS = 4096


def rsa_verify(public_key_pem, message, signature) -> bool:
    """Verify RSA/SHA-256 signatures under the Medimo verification profile."""
    if not isinstance(public_key_pem, (bytes, str)):
        return False
    if not isinstance(message, bytes) or not isinstance(signature, bytes):
        return False

    try:
        pem = (public_key_pem.encode("ascii")
               if isinstance(public_key_pem, str) else public_key_pem).strip()
        # The contract takes public-key PEM, not certificates, DER or private keys.
        if not pem.startswith((b"-----BEGIN PUBLIC KEY-----",
                               b"-----BEGIN RSA PUBLIC KEY-----")):
            return False
        public_key = RSA.import_key(pem)
        if not isinstance(public_key, RSA.RsaKey) or public_key.has_private():
            return False

        n, e = public_key.n, public_key.e
        if n <= 0 or n % 2 == 0:
            return False
        if not _MIN_VERIFY_BITS <= n.bit_length() <= _MAX_VERIFY_BITS:
            return False
        if not 3 <= e < n or e % 2 == 0:
            return False
        # Public component consistency checks; cannot establish factorization
        # or provenance using only the public components.
        RSA.construct((n, e), consistency_check=True)
    except (ValueError, TypeError, IndexError, OverflowError, AttributeError):
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
    expected_null = _emsa_pkcs1_v1_5_encode_digest(digest, k, include_null=True)
    expected_absent = _emsa_pkcs1_v1_5_encode_digest(digest, k, include_null=False)

    matches_null = hmac.compare_digest(recovered_em, expected_null)
    matches_absent = hmac.compare_digest(recovered_em, expected_absent)
    return matches_null | matches_absent
