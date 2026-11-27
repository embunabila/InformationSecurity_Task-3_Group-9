"""Shared error classes for the data sharing feature."""


class KeyUnlockError(Exception):
    """Wrong password, or the private key could not be unlocked."""


class InvalidKeyPackageError(Exception):
    """The key package is malformed or not meant for this request or user."""


class ShareAccessError(Exception):
    """No access, or the request was rejected, revoked, or has expired."""


class KeyLockedError(Exception):
    """Too many failed password attempts; the private key is temporarily locked."""


class InvalidPdfError(Exception):
    """Not a PDF, a damaged PDF, or a password-protected PDF."""


class AlreadySignedError(Exception):
    """The PDF already has a signature field that holds a signature (/V)."""


class InvalidSignatureError(Exception):
    """The signature is broken or tampered with: verification status "invalid"."""


class UnsupportedSignatureError(Exception):
    """A valid signature format that Medimo does not support: status "unsupported"."""


class KeyExpiredError(Exception):
    """The user's signing key is past its expires_at date."""