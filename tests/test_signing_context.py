import unittest
from unittest.mock import patch

from crypto_core import (
    _encode_context,
    encrypt_blob,
    decrypt_blob,
    InvalidEnvelopeError,
)


class TestSigningKeyContext(unittest.TestCase):

    def setUp(self):
        self.kek = bytes(range(32))
        self.data = b"dummy signing private key material"

        self.signing_context = {
            "owner_id": 1,
            "kind": "signing_key",
            "item_id": "signing_key",
        }

        self.private_context = {
            "owner_id": 1,
            "kind": "private_key",
            "item_id": "private_key",
        }

    def test_valid_signing_key_context(self):
        encoded = _encode_context(self.signing_context)

        expected = (
            b'{"item_id":"signing_key",'
            b'"kind":"signing_key","owner_id":1}'
        )

        self.assertEqual(encoded, expected)

    def test_invalid_signing_key_item_id(self):
        invalid_values = [
            "",
            "private_key",
            "profile",
            "SIGNING_KEY",
            "signing_key ",
            "12345678-1234-1234-1234-123456789abc",
            None,
            123,
            True,
        ]

        for item_id in invalid_values:
            with self.subTest(item_id=item_id):
                context = {
                    **self.signing_context,
                    "item_id": item_id,
                }

                with self.assertRaises(ValueError):
                    _encode_context(context)

    def test_invalid_signing_key_owner_id(self):
        invalid_values = [
            0,
            -1,
            True,
            False,
            "1",
            1.0,
            None,
        ]

        for owner_id in invalid_values:
            with self.subTest(owner_id=owner_id):
                context = {
                    **self.signing_context,
                    "owner_id": owner_id,
                }

                with self.assertRaises(ValueError):
                    _encode_context(context)

    def test_signing_key_aes_round_trip(self):
        encrypted = encrypt_blob(
            self.data,
            self.kek,
            "AES",
            self.signing_context,
        )

        decrypted = decrypt_blob(
            encrypted,
            self.kek,
            "AES",
            self.signing_context,
        )

        self.assertEqual(decrypted, self.data)

    def test_signing_key_rejected_as_private_key(self):
        encrypted = encrypt_blob(
            self.data,
            self.kek,
            "AES",
            self.signing_context,
        )

        with self.assertRaises(InvalidEnvelopeError):
            decrypt_blob(
                encrypted,
                self.kek,
                "AES",
                self.private_context,
            )

    def test_private_key_rejected_as_signing_key(self):
        encrypted = encrypt_blob(
            self.data,
            self.kek,
            "AES",
            self.private_context,
        )

        with self.assertRaises(InvalidEnvelopeError):
            decrypt_blob(
                encrypted,
                self.kek,
                "AES",
                self.signing_context,
            )

    def test_signing_key_context_separation_between_users(self):
        other_user_context = {
            **self.signing_context,
            "owner_id": 2,
        }

        for source, target in (
            (self.signing_context, other_user_context),
            (other_user_context, self.signing_context),
        ):
            with self.subTest(source=source, target=target):
                encrypted = encrypt_blob(
                    self.data,
                    self.kek,
                    "AES",
                    source,
                )

                with self.assertRaises(InvalidEnvelopeError):
                    decrypt_blob(
                        encrypted,
                        self.kek,
                        "AES",
                        target,
                    )

    def test_tampered_authenticated_context(self):
        encrypted = encrypt_blob(
            self.data,
            self.kek,
            "AES",
            self.signing_context,
        )

        original_context = _encode_context(
            self.signing_context
        )

        tampered_context = original_context.replace(
            b'"owner_id":1',
            b'"owner_id":2',
        )

        self.assertNotEqual(
            original_context,
            tampered_context,
        )

        with patch(
            "crypto_core._encode_context",
            return_value=tampered_context,
        ):
            with self.assertRaises(InvalidEnvelopeError):
                decrypt_blob(
                    encrypted,
                    self.kek,
                    "AES",
                    self.signing_context,
                )


if __name__ == "__main__":
    unittest.main()