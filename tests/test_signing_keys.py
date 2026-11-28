import base64
import sqlite3
import tempfile
import unittest

from contextlib import closing, ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import pkcs1_15

from werkzeug.security import generate_password_hash

import db
import signing_keys

from certificate import (
    build_self_signed_certificate,
    parse_certificate,
)

from crypto_core import (
    decrypt_blob,
    InvalidEnvelopeError,
)

from der import (
    decode_value,
    parse_der,
)

from share_errors import KeyUnlockError, KeyLockedError
from crypto_core import encrypt_blob
from signing_keys import unlock_signing_key

from signing_keys import (
    _emsa_pkcs1_v1_5_encode,
    _emsa_pkcs1_v1_5_encode_digest,
    _derive_signing_kek,
    _generate_signing_kek_salt,
    _signing_key_context,
    signing_public_key_fingerprint,
    generate_signing_keypair,
    get_signing_key,
    find_signer_by_fingerprint,
    rsa_sign,
    rsa_verify,
)

from user_keys import (
    generate_user_keypair,
    public_key_fingerprint,
)


# ============================================================
# Stage 3a: EMSA known-answer fixtures
# ============================================================

ABC_DIGEST = bytes.fromhex(
    "ba7816bf8f01cfea414140de5dae2223"
    "b00361a396177a9cb410ff61f20015ad"
)

EMPTY_DIGEST = bytes.fromhex(
    "e3b0c44298fc1c149afbf4c8996fb924"
    "27ae41e4649b934ca495991b7852b855"
)

NULL_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)

ABSENT_PREFIX = bytes.fromhex(
    "302f300b06096086480165030402010420"
)


# ============================================================
# Stage 3a: Existing EMSA tests
# ============================================================


class TestEMSAPKCS1v15(unittest.TestCase):

    def test_known_encoded_message(self):
        expected = bytes.fromhex(
            "0001 ffffffffffffffffffff 00"
            "3031300d060960864801650304020105000420"
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad"
        )

        self.assertEqual(len(expected), 64)

        self.assertEqual(
            _emsa_pkcs1_v1_5_encode(b"abc", 64),
            expected,
        )

        self.assertEqual(
            _emsa_pkcs1_v1_5_encode_digest(
                ABC_DIGEST, 64
            ),
            expected,
        )

    def test_null_digestinfo_prefix(self):
        em = _emsa_pkcs1_v1_5_encode_digest(
            ABC_DIGEST, 256
        )

        self.assertEqual(
            em[-51:],
            NULL_PREFIX + ABC_DIGEST,
        )

    def test_absent_digestinfo_prefix(self):
        em = _emsa_pkcs1_v1_5_encode_digest(
            ABC_DIGEST,
            256,
            include_null=False,
        )

        self.assertEqual(
            em[-49:],
            ABSENT_PREFIX + ABC_DIGEST,
        )

    def test_modulus_lengths(self):
        for k, null_ps, absent_ps in (
            (256, 202, 204),
            (384, 330, 332),
            (512, 458, 460),
            (257, 203, 205),
        ):
            for include_null, ps, prefix in (
                (True, null_ps, NULL_PREFIX),
                (False, absent_ps, ABSENT_PREFIX),
            ):
                with self.subTest(
                    k=k,
                    include_null=include_null,
                ):
                    expected = (
                        b"\x00\x01"
                        + b"\xff" * ps
                        + b"\x00"
                        + prefix
                        + ABC_DIGEST
                    )

                    em = _emsa_pkcs1_v1_5_encode_digest(
                        ABC_DIGEST,
                        k,
                        include_null=include_null,
                    )

                    self.assertEqual(len(em), k)
                    self.assertEqual(em, expected)

    def test_minimum_padding_boundary(self):
        for k, include_null, prefix in (
            (62, True, NULL_PREFIX),
            (60, False, ABSENT_PREFIX),
        ):
            with self.subTest(k=k):
                expected = (
                    bytes.fromhex(
                        "0001 ffffffffffffffff 00"
                    )
                    + prefix
                    + ABC_DIGEST
                )

                self.assertEqual(
                    _emsa_pkcs1_v1_5_encode_digest(
                        ABC_DIGEST,
                        k,
                        include_null=include_null,
                    ),
                    expected,
                )

    def test_insufficient_encoded_message_length(self):
        for k, include_null in (
            (61, True),
            (59, False),
            (1, True),
            (1, False),
        ):
            with self.subTest(
                k=k,
                include_null=include_null,
            ):
                with self.assertRaises(ValueError):
                    _emsa_pkcs1_v1_5_encode_digest(
                        ABC_DIGEST,
                        k,
                        include_null=include_null,
                    )

    def test_invalid_digest_types(self):
        for digest in (
            None,
            "x" * 32,
            32,
            bytearray(32),
            memoryview(bytes(32)),
            True,
        ):
            with self.subTest(
                digest_type=type(digest).__name__
            ):
                with self.assertRaises(ValueError):
                    _emsa_pkcs1_v1_5_encode_digest(
                        digest, 256
                    )

    def test_invalid_digest_lengths(self):
        for length in (0, 1, 31, 33, 64):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    _emsa_pkcs1_v1_5_encode_digest(
                        bytes(length), 256
                    )

    def test_invalid_message_types(self):
        for message in (
            None, "abc", 123,
            bytearray(b"abc"),
            memoryview(b"abc"),
            True,
        ):
            with self.subTest(
                message_type=type(message).__name__
            ):
                with self.assertRaises(ValueError):
                    _emsa_pkcs1_v1_5_encode(
                        message, 256
                    )

    def test_invalid_em_lengths(self):
        for k in (
            0, -1, True, False, 256.0,
            "256", None, 513, 10**100,
        ):
            with self.subTest(k=k):
                with self.assertRaises(ValueError):
                    _emsa_pkcs1_v1_5_encode_digest(
                        ABC_DIGEST, k
                    )

    def test_invalid_include_null(self):
        for value in (None, 0, 1, "True", b"true"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    _emsa_pkcs1_v1_5_encode_digest(
                        ABC_DIGEST,
                        256,
                        include_null=value,
                    )

    def test_exact_padding_and_digest_placement(self):
        digest = bytes(range(32))

        for include_null, separator, prefix in (
            (True, 332, NULL_PREFIX),
            (False, 334, ABSENT_PREFIX),
        ):
            with self.subTest(
                include_null=include_null
            ):
                em = _emsa_pkcs1_v1_5_encode_digest(
                    digest,
                    384,
                    include_null=include_null,
                )

                self.assertEqual(len(em), 384)
                self.assertEqual(em[:2], b"\x00\x01")

                self.assertEqual(
                    em[2:separator],
                    b"\xff" * (separator - 2),
                )

                self.assertEqual(
                    em[separator:separator + 1],
                    b"\x00",
                )

                self.assertEqual(
                    em[separator + 1:-32],
                    prefix,
                )

                self.assertEqual(em[-32:], digest)

    def test_empty_message(self):
        expected = (
            b"\x00\x01"
            + b"\xff" * 202
            + b"\x00"
            + NULL_PREFIX
            + EMPTY_DIGEST
        )

        self.assertEqual(
            _emsa_pkcs1_v1_5_encode(b"", 256),
            expected,
        )

    def test_message_with_absent_parameter(self):
        expected = (
            b"\x00\x01"
            + b"\xff" * 204
            + b"\x00"
            + ABSENT_PREFIX
            + ABC_DIGEST
        )

        self.assertEqual(
            _emsa_pkcs1_v1_5_encode(
                b"abc",
                256,
                include_null=False,
            ),
            expected,
        )


# ============================================================
# Stage 3b: Existing RSA signing tests
# ============================================================


class TestRSASign(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.private_key = RSA.generate(3072)
        cls.other_key = RSA.generate(3072)
        cls.message = b"Medimo RSA signing test"

    def reference_signature(self, message, key=None):
        if key is None:
            key = self.private_key

        return pkcs1_15.new(key).sign(
            SHA256.new(message)
        )

    def test_successful_rsa3072_signing(self):
        signature = rsa_sign(
            self.private_key,
            self.message,
        )

        self.assertIsInstance(signature, bytes)

        self.assertEqual(
            self.private_key.size_in_bits(),
            3072,
        )

        self.assertEqual(
            len(signature),
            self.private_key.size_in_bytes(),
        )

    def test_signature_length(self):
        self.assertEqual(
            len(rsa_sign(self.private_key, self.message)),
            384,
        )

    def test_signature_representative_range_and_recovered_em(self):
        signature = rsa_sign(
            self.private_key,
            b"abc",
        )

        s = int.from_bytes(signature, "big")

        self.assertGreaterEqual(s, 0)
        self.assertLess(s, self.private_key.n)

        expected_em = (
            b"\x00\x01"
            + b"\xff" * 330
            + b"\x00"
            + NULL_PREFIX
            + ABC_DIGEST
        )

        m = pow(
            s,
            self.private_key.e,
            self.private_key.n,
        )

        self.assertEqual(
            m.to_bytes(384, "big"),
            expected_em,
        )

    def test_deterministic_signature(self):
        first = rsa_sign(
            self.private_key, self.message
        )

        second = rsa_sign(
            self.private_key, self.message
        )

        self.assertEqual(first, second)

    def test_different_messages(self):
        self.assertNotEqual(
            rsa_sign(self.private_key, b"message A"),
            rsa_sign(self.private_key, b"message B"),
        )

    def test_different_private_keys(self):
        self.assertNotEqual(
            self.private_key.n,
            self.other_key.n,
        )

        self.assertNotEqual(
            rsa_sign(self.private_key, self.message),
            rsa_sign(self.other_key, self.message),
        )

    def test_empty_message(self):
        signature = rsa_sign(
            self.private_key, b""
        )

        self.assertEqual(
            signature,
            self.reference_signature(b""),
        )

    def test_invalid_message_types(self):
        for value in (
            None, "abc", 123, True,
            bytearray(b"abc"),
            memoryview(b"abc"),
        ):
            with self.subTest(
                value_type=type(value).__name__
            ):
                with self.assertRaises(ValueError):
                    rsa_sign(self.private_key, value)

    def test_public_key_rejected(self):
        with self.assertRaises(ValueError):
            rsa_sign(
                self.private_key.public_key(),
                self.message,
            )

    def test_invalid_key_inputs(self):
        for key in (
            None, 123, True,
            "private key", b"not a key", object(),
        ):
            with self.subTest(
                key_type=type(key).__name__
            ):
                with self.assertRaises(ValueError):
                    rsa_sign(key, self.message)

    def test_wrong_key_sizes_rejected(self):
        for bits in (2048, 4096):
            with self.subTest(bits=bits):
                key = RSA.generate(bits)

                with self.assertRaises(ValueError):
                    rsa_sign(key, self.message)

    def test_reference_verification(self):
        signature = rsa_sign(
            self.private_key, self.message
        )

        pkcs1_15.new(
            self.private_key.public_key()
        ).verify(
            SHA256.new(self.message),
            signature,
        )

    def test_exact_reference_signature(self):
        for message in (
            b"abc",
            self.message,
            b"\x00\xff\x80",
            bytes(range(256)),
        ):
            with self.subTest(message=message):
                self.assertEqual(
                    rsa_sign(self.private_key, message),
                    self.reference_signature(message),
                )

    def test_leading_zero_signature_serialization(self):
        for counter in range(8192):
            message = (
                b"leading-zero:"
                + counter.to_bytes(4, "big")
            )

            expected = self.reference_signature(message)

            if expected[0] == 0:
                break
        else:
            self.fail(
                "No leading-zero signature found within search limit"
            )

        actual = rsa_sign(
            self.private_key, message
        )

        self.assertEqual(len(actual), 384)
        self.assertEqual(actual[:1], b"\x00")
        self.assertEqual(actual, expected)

    def test_inconsistent_rsa_private_key_rejected(self):
        key = self.private_key

        inconsistent = RSA.construct(
            (
                key.n,
                key.e,
                key.d + 1,
                key.p,
                key.q,
            ),
            consistency_check=False,
        )

        with self.assertRaises(ValueError):
            rsa_sign(inconsistent, self.message)

    def test_message_representative_out_of_range(self):
        k = self.private_key.size_in_bytes()

        for m in (
            self.private_key.n,
            self.private_key.n + 1,
        ):
            with self.subTest(
                m_equals_n=m == self.private_key.n
            ):
                with patch(
                    "signing_keys._emsa_pkcs1_v1_5_encode",
                    return_value=m.to_bytes(k, "big"),
                ):
                    with self.assertRaisesRegex(
                        ValueError,
                        "representative out of range",
                    ):
                        rsa_sign(
                            self.private_key,
                            self.message,
                        )


# ============================================================
# Stage 3c: Existing RSA verification tests
# ============================================================


class TestRSAVerify(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.keys = {
            bits: RSA.generate(
                bits,
                e=3 if bits == 2048 else 65537,
            )
            for bits in (2048, 2049, 3072, 4096)
        }

        cls.key = cls.keys[2048]
        cls.pem = cls.key.public_key().export_key()
        cls.k = cls.key.size_in_bytes()
        cls.message = b"abc"

        cls.signature = pkcs1_15.new(
            cls.key
        ).sign(
            SHA256.new(cls.message)
        )

    @staticmethod
    def reference_signature(key, message):
        return pkcs1_15.new(key).sign(
            SHA256.new(message)
        )

    def raw_sign_em(self, em):
        """Test-only private operation for independently built EM."""

        self.assertEqual(len(em), self.k)

        m = int.from_bytes(em, "big")
        self.assertLess(m, self.key.n)

        s = pow(m, self.key.d, self.key.n)

        signature = s.to_bytes(self.k, "big")

        self.assertEqual(
            pow(
                s,
                self.key.e,
                self.key.n,
            ).to_bytes(self.k, "big"),
            em,
        )

        return signature

    def independent_em(self, prefix=NULL_PREFIX):
        t = prefix + ABC_DIGEST

        return (
            b"\x00\x01"
            + b"\xff" * (self.k - len(t) - 3)
            + b"\x00"
            + t
        )

    def assert_bad_em(self, em):
        signature = self.raw_sign_em(em)

        self.assertIs(
            rsa_verify(
                self.pem,
                self.message,
                signature,
            ),
            False,
        )

    @staticmethod
    def public_pem(n, e):
        """Independently construct PKCS#1 public-key PEM."""

        def tlv(tag, content):
            length = len(content)

            if length < 128:
                size = bytes([length])
            else:
                value = length.to_bytes(
                    (length.bit_length() + 7) // 8,
                    "big",
                )

                size = (
                    bytes([0x80 | len(value)])
                    + value
                )

            return bytes([tag]) + size + content

        def integer(value):
            bits = (
                value.bit_length()
                if value >= 0
                else (~value).bit_length()
            )

            return tlv(
                2,
                value.to_bytes(
                    max(1, (bits + 8) // 8),
                    "big",
                    signed=True,
                ),
            )

        der = tlv(
            0x30,
            integer(n) + integer(e),
        )

        return (
            b"-----BEGIN RSA PUBLIC KEY-----\n"
            + base64.encodebytes(der)
            + b"-----END RSA PUBLIC KEY-----\n"
        )

    def test_successful_verification_of_rsa_sign(self):
        key = self.keys[3072]

        self.assertIs(
            rsa_verify(
                key.public_key().export_key(),
                self.message,
                rsa_sign(key, self.message),
            ),
            True,
        )

    def test_reference_interoperability(self):
        for message in (
            b"abc",
            b"\x00\xff\x80",
            bytes(range(256)),
        ):
            with self.subTest(message=message):
                self.assertIs(
                    rsa_verify(
                        self.pem,
                        message,
                        self.reference_signature(
                            self.key, message
                        ),
                    ),
                    True,
                )

    def test_supported_modulus_sizes(self):
        for bits, key in self.keys.items():
            with self.subTest(bits=bits):
                self.assertEqual(
                    key.n.bit_length(),
                    bits,
                )

                signature = self.reference_signature(
                    key, self.message
                )

                self.assertEqual(
                    len(signature),
                    (bits + 7) // 8,
                )

                self.assertIs(
                    rsa_verify(
                        key.public_key().export_key(),
                        self.message,
                        signature,
                    ),
                    True,
                )

    def test_valid_digestinfo_null(self):
        self.assertIs(
            rsa_verify(
                self.pem,
                self.message,
                self.raw_sign_em(
                    self.independent_em(NULL_PREFIX)
                ),
            ),
            True,
        )

    def test_valid_digestinfo_absent(self):
        self.assertIs(
            rsa_verify(
                self.pem,
                self.message,
                self.raw_sign_em(
                    self.independent_em(ABSENT_PREFIX)
                ),
            ),
            True,
        )

    def test_empty_message_verification(self):
        self.assertIs(
            rsa_verify(
                self.pem,
                b"",
                self.reference_signature(
                    self.key, b""
                ),
            ),
            True,
        )

    def test_modified_message(self):
        self.assertIs(
            rsa_verify(
                self.pem, b"abd", self.signature
            ),
            False,
        )

    def test_signature_one_bit_modified(self):
        tampered = (
            self.signature[:-1]
            + bytes([self.signature[-1] ^ 1])
        )

        self.assertIs(
            rsa_verify(
                self.pem, self.message, tampered
            ),
            False,
        )

    def test_signature_from_other_key(self):
        other = RSA.generate(2048)

        self.assertIs(
            rsa_verify(
                other.public_key().export_key(),
                self.message,
                self.signature,
            ),
            False,
        )

    def test_wrong_signature_lengths(self):
        for signature in (
            b"",
            self.signature[1:],
            b"\x00" + self.signature,
            self.signature + b"\x00",
        ):
            with self.subTest(length=len(signature)):
                self.assertIs(
                    rsa_verify(
                        self.pem,
                        self.message,
                        signature,
                    ),
                    False,
                )

    def test_signature_representative_out_of_range(self):
        for s in (
            self.key.n,
            self.key.n + 1,
            (1 << (8 * self.k)) - 1,
        ):
            with self.subTest(representative=s):
                self.assertIs(
                    rsa_verify(
                        self.pem,
                        self.message,
                        s.to_bytes(self.k, "big"),
                    ),
                    False,
                )

    def test_zero_signature_rejected(self):
        self.assertIs(
            rsa_verify(
                self.pem,
                self.message,
                bytes(self.k),
            ),
            False,
        )

    def test_malformed_public_key_pem(self):
        for pem in (
            b"",
            b"not a PEM",
            (
                b"-----BEGIN PUBLIC KEY-----\n"
                b"!\n"
                b"-----END PUBLIC KEY-----"
            ),
            self.pem[:40],
            "-----BEGIN PUBLIC KEY-----\n\u2603",
        ):
            with self.subTest(pem=pem):
                self.assertIs(
                    rsa_verify(
                        pem,
                        self.message,
                        self.signature,
                    ),
                    False,
                )

    def test_non_rsa_public_key(self):
        pem = ECC.generate(
            curve="P-256"
        ).public_key().export_key(
            format="PEM"
        )

        self.assertIs(
            rsa_verify(
                pem,
                self.message,
                self.signature,
            ),
            False,
        )

    def test_private_key_and_non_pem_rejected(self):
        for pem in (
            self.key.export_key(),
            self.key.public_key().export_key(
                format="DER"
            ),
        ):
            with self.subTest(pem_format=pem[:20]):
                self.assertIs(
                    rsa_verify(
                        pem,
                        self.message,
                        self.signature,
                    ),
                    False,
                )

    def test_pem_text_and_pkcs1_public_key(self):
        for pem in (
            self.pem.decode("ascii"),
            self.public_pem(
                self.key.n,
                self.key.e,
            ),
        ):
            with self.subTest(
                pem_type=type(pem).__name__
            ):
                self.assertIs(
                    rsa_verify(
                        pem,
                        self.message,
                        self.signature,
                    ),
                    True,
                )

    def test_unsupported_key_sizes(self):
        for bits in (2047, 4097):
            with self.subTest(bits=bits):
                key = RSA.generate(bits)

                self.assertEqual(
                    key.n.bit_length(),
                    bits,
                )

                signature = self.reference_signature(
                    key, self.message
                )

                self.assertEqual(
                    len(signature),
                    (bits + 7) // 8,
                )

                self.assertIs(
                    rsa_verify(
                        key.public_key().export_key(),
                        self.message,
                        signature,
                    ),
                    False,
                )

    def test_invalid_public_exponents(self):
        for e in (
            0, 1, 2, 4, -3,
            self.key.n,
            self.key.n + 2,
        ):
            with self.subTest(exponent=e):
                pem = self.public_pem(
                    self.key.n, e
                )

                self.assertIs(
                    rsa_verify(
                        pem,
                        self.message,
                        self.signature,
                    ),
                    False,
                )

    def test_invalid_public_modulus(self):
        for n in (
            0,
            -self.key.n,
            self.key.n - 1,
        ):
            with self.subTest(modulus=n):
                self.assertIs(
                    rsa_verify(
                        self.public_pem(n, 65537),
                        self.message,
                        self.signature,
                    ),
                    False,
                )

    def test_inconsistent_public_components(self):
        n = 3 * ((1 << 2046) + 1)

        self.assertEqual(n.bit_length(), 2048)

        self.assertIs(
            rsa_verify(
                self.public_pem(n, 3),
                self.message,
                self.signature,
            ),
            False,
        )

    def test_invalid_input_types(self):
        for value in (
            None, 1, True,
            bytearray(b"abc"),
            memoryview(b"abc"),
            object(),
        ):
            with self.subTest(
                value_type=type(value).__name__
            ):
                self.assertIs(
                    rsa_verify(
                        value,
                        self.message,
                        self.signature,
                    ),
                    False,
                )

                self.assertIs(
                    rsa_verify(
                        self.pem,
                        value,
                        self.signature,
                    ),
                    False,
                )

                self.assertIs(
                    rsa_verify(
                        self.pem,
                        self.message,
                        value,
                    ),
                    False,
                )

        self.assertIs(
            rsa_verify(
                self.pem,
                "abc",
                self.signature,
            ),
            False,
        )

        self.assertIs(
            rsa_verify(
                self.pem,
                self.message,
                "signature",
            ),
            False,
        )

    def test_valid_leading_zero_signature(self):
        for counter in range(8192):
            message = (
                b"verify-leading-zero:"
                + counter.to_bytes(4, "big")
            )

            signature = self.reference_signature(
                self.key, message
            )

            if signature[0] == 0:
                break
        else:
            self.fail(
                "No leading-zero signature found within search limit"
            )

        self.assertEqual(len(signature), self.k)

        self.assertIs(
            rsa_verify(
                self.pem,
                message,
                signature,
            ),
            True,
        )

        self.assertIs(
            rsa_verify(
                self.pem,
                message,
                signature[1:],
            ),
            False,
        )

    def test_malformed_em_incorrect_header(self):
        em = self.independent_em()

        for header in (
            b"\x00\x00",
            b"\x00\x02",
            b"\x01\x01",
        ):
            with self.subTest(header=header):
                self.assert_bad_em(
                    header + em[2:]
                )

    def test_malformed_em_insufficient_ff_padding(self):
        t = NULL_PREFIX + ABC_DIGEST

        em = (
            b"\x00\x01"
            + b"\xff" * 7
            + b"\x00"
            + b"\xaa" * (self.k - 10 - len(t))
            + t
        )

        self.assert_bad_em(em)

    def test_malformed_em_incorrect_separator(self):
        em = self.independent_em()
        separator = self.k - 52

        self.assertEqual(em[separator], 0)

        self.assert_bad_em(
            em[:separator]
            + b"\x01"
            + em[separator + 1:]
        )

    def test_malformed_em_incorrect_digestinfo(self):
        em = self.independent_em()

        wrong_prefix = bytes.fromhex(
            "3031300d060960864801650304020205000420"
        )

        self.assert_bad_em(
            em[:-51]
            + wrong_prefix
            + ABC_DIGEST
        )

    def test_malformed_em_incorrect_digest(self):
        em = self.independent_em()

        self.assert_bad_em(
            em[:-1]
            + bytes([em[-1] ^ 1])
        )

    def test_malformed_em_trailing_garbage(self):
        t = NULL_PREFIX + ABC_DIGEST

        for garbage in (
            b"\x00",
            b"\x01\x02\x03",
            b"\xaa" * 32,
        ):
            with self.subTest(garbage=garbage):
                em = (
                    b"\x00\x01"
                    + b"\xff" * (
                        self.k - len(t) - len(garbage) - 3
                    )
                    + b"\x00"
                    + t
                    + garbage
                )

                self.assert_bad_em(em)

    def test_malformed_em_correct_digest_wrong_padding(self):
        em = self.independent_em()

        for index, value in (
            (2, 0x00),
            (10, 0x7f),
            (100, 0xfe),
        ):
            with self.subTest(
                index=index,
                value=value,
            ):
                self.assert_bad_em(
                    em[:index]
                    + bytes([value])
                    + em[index + 1:]
                )

    def test_hash_once_and_both_full_comparisons(self):
        from signing_keys import hmac

        for prefix in (
            NULL_PREFIX,
            ABSENT_PREFIX,
        ):
            em = self.independent_em(prefix)
            signature = self.raw_sign_em(em)

            with self.subTest(prefix=prefix):
                with patch(
                    "signing_keys.SHA256.new",
                    wraps=SHA256.new,
                ) as hash_spy:

                    with patch(
                        "signing_keys.hmac.compare_digest",
                        wraps=hmac.compare_digest,
                    ) as compare_spy:

                        self.assertIs(
                            rsa_verify(
                                self.pem,
                                self.message,
                                signature,
                            ),
                            True,
                        )

                hash_spy.assert_called_once_with(
                    self.message
                )

                self.assertEqual(
                    compare_spy.call_count,
                    2,
                )

                self.assertEqual(
                    compare_spy.call_args_list[0].args,
                    (
                        em,
                        self.independent_em(NULL_PREFIX),
                    ),
                )

                self.assertEqual(
                    compare_spy.call_args_list[1].args,
                    (
                        em,
                        self.independent_em(ABSENT_PREFIX),
                    ),
                )


# ============================================================
# Stage 5a: Existing signing-key helper tests
# ============================================================


class TestSigningKeyHelpers(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.keys = {
            bits: RSA.generate(bits)
            for bits in (
                2048, 2049, 3072, 4096
            )
        }

        cls.key = cls.keys[3072].public_key()

        cls.pem = cls.key.export_key(
            format="PEM"
        )

        cls.der = cls.key.export_key(
            format="DER"
        )

        cls.password = "Medimo-密码"
        cls.salt = bytes(range(16))

    def test_fingerprint_supported_sizes(self):
        for bits in (2048, 3072, 4096):
            with self.subTest(bits=bits):
                key = self.keys[bits].public_key()

                self.assertEqual(
                    key.size_in_bits(),
                    bits,
                )

                result = signing_public_key_fingerprint(
                    key.export_key()
                )

                self.assertEqual(len(result), 79)

    def test_fingerprint_non_byte_aligned(self):
        key = self.keys[2049].public_key()

        self.assertEqual(key.size_in_bits(), 2049)
        self.assertEqual(key.size_in_bytes(), 257)

        self.assertEqual(
            len(
                signing_public_key_fingerprint(
                    key.export_key()
                )
            ),
            79,
        )

    def test_fingerprint_exact_format(self):
        result = signing_public_key_fingerprint(
            self.pem
        )

        self.assertEqual(len(result), 79)

        self.assertRegex(
            result,
            r"\A[0-9A-F]{4}( [0-9A-F]{4}){15}\Z",
        )

        self.assertEqual(
            len(result.replace(" ", "")),
            64,
        )

    def test_fingerprint_independent_digest(self):
        expected = SHA256.new(
            self.der
        ).digest().hex().upper()

        actual = signing_public_key_fingerprint(
            self.pem
        )

        self.assertEqual(
            actual.replace(" ", ""),
            expected,
        )

    def test_fingerprint_equivalent_representations(self):
        pkcs1_pem = TestRSAVerify.public_pem(
            self.key.n,
            self.key.e,
        )

        pkcs1_der = base64.b64decode(
            b"".join(
                pkcs1_pem.splitlines()[1:-1]
            )
        )

        def tlv(tag, content):
            size = len(content)

            if size < 128:
                length = bytes([size])
            else:
                raw = size.to_bytes(
                    (size.bit_length() + 7) // 8,
                    "big",
                )

                length = (
                    bytes([0x80 | len(raw)])
                    + raw
                )

            return (
                bytes([tag])
                + length
                + content
            )

        absent = tlv(
            0x30,
            bytes.fromhex(
                "300b06092a864886f70d010101"
            )
            + tlv(
                0x03,
                b"\x00" + pkcs1_der,
            ),
        )

        expected = signing_public_key_fingerprint(
            self.pem
        )

        representations = (
            self.pem.decode("ascii"),
            self.der,
            pkcs1_pem,
            pkcs1_der,
            absent,
            self.pem.replace(b"\n", b"\r\n"),
        )

        for representation in representations:
            with self.subTest(
                input_type=type(representation).__name__
            ):
                self.assertEqual(
                    signing_public_key_fingerprint(
                        representation
                    ),
                    expected,
                )

    def test_fingerprint_task2_compatibility(self):
        self.assertEqual(
            signing_public_key_fingerprint(
                self.pem
            ),
            public_key_fingerprint(
                self.pem
            ),
        )

        self.assertEqual(
            signing_public_key_fingerprint(
                self.der
            ),
            public_key_fingerprint(
                self.der
            ),
        )

    def test_fingerprint_different_keys(self):
        values = [
            signing_public_key_fingerprint(
                key.public_key().export_key()
            )
            for key in self.keys.values()
        ]

        self.assertEqual(
            len(set(values)),
            len(values),
        )

    def test_fingerprint_invalid_keys(self):
        ecc = ECC.generate(
            curve="P-256"
        ).public_key()

        private = self.keys[3072]

        mislabeled = self.pem.replace(
            b"PUBLIC KEY",
            b"RSA PUBLIC KEY",
        )

        values = (
            ("none", None),
            ("integer", 1),
            ("boolean", True),
            ("object", object()),
            ("bytearray", bytearray(self.der)),
            ("empty_bytes", b""),
            ("random_bytes", b"not a key"),
            ("truncated_pem", self.pem[:40]),
            ("der_trailing_bytes", self.der + b"\x00"),
            ("pem_trailing_garbage", self.pem + b"garbage"),
            ("mislabeled_pem", mislabeled),
            ("ecc_public_pem", ecc.export_key(format="PEM")),
            ("ecc_public_der", ecc.export_key(format="DER")),
            ("rsa_private_pem", private.export_key()),
            ("rsa_private_der", private.export_key(format="DER")),
        )

        for label, value in values:
            with self.subTest(
                case=label,
                input_type=type(value).__name__,
            ):
                with self.assertRaises(ValueError):
                    signing_public_key_fingerprint(value)

    def test_fingerprint_unsupported_sizes(self):
        small = RSA.generate(
            1024
        ).public_key().export_key()

        oversized = TestRSAVerify.public_pem(
            (1 << 4096) | 1,
            65537,
        )

        for pem in (small, oversized):
            with self.assertRaises(ValueError):
                signing_public_key_fingerprint(pem)

    def test_fingerprint_invalid_exponents(self):
        n = self.key.n

        for e in (
            0, 1, 2, 4, -3,
            n,
            n + 2,
            self.keys[3072].p,
        ):
            with self.subTest(e=e):
                with self.assertRaises(ValueError):
                    signing_public_key_fingerprint(
                        TestRSAVerify.public_pem(n, e)
                    )

    def test_fingerprint_invalid_moduli(self):
        for n in (
            0,
            -self.key.n,
            self.key.n - 1,
        ):
            with self.subTest(n=n):
                with self.assertRaises(ValueError):
                    signing_public_key_fingerprint(
                        TestRSAVerify.public_pem(
                            n, 65537
                        )
                    )

    def test_signing_salt_generation(self):
        from user_keys import _generate_kek_salt

        salts = (
            _generate_signing_kek_salt(),
            _generate_signing_kek_salt(),
            _generate_kek_salt(),
        )

        for salt in salts:
            self.assertIsInstance(salt, bytes)
            self.assertEqual(len(salt), 16)

        self.assertEqual(len(set(salts)), 3)

    def test_kek_deterministic_known_answer(self):
        expected = bytes.fromhex(
            "57262cc43b4c2f63d801e9e7d4de00f6"
            "b635aaaf7b9f5bf9a79f48e1fa07a070"
        )

        first = _derive_signing_kek(
            self.password,
            self.salt,
        )

        second = _derive_signing_kek(
            self.password,
            self.salt,
        )

        self.assertEqual(first, expected)
        self.assertEqual(second, expected)

    def test_kek_different_password(self):
        self.assertNotEqual(
            _derive_signing_kek(
                self.password, self.salt
            ),
            _derive_signing_kek(
                self.password + "!", self.salt
            ),
        )

    def test_kek_different_salt(self):
        self.assertNotEqual(
            _derive_signing_kek(
                self.password, self.salt
            ),
            _derive_signing_kek(
                self.password, b"\xff" * 16
            ),
        )

    def test_kek_length(self):
        result = _derive_signing_kek(
            self.password,
            self.salt,
        )

        self.assertIsInstance(result, bytes)
        self.assertEqual(len(result), 32)

    def test_kek_invalid_passwords(self):
        for password in (
            None,
            b"password",
            1,
            True,
            "",
            "\ud800",
        ):
            with self.subTest(
                input_type=type(password).__name__
            ):
                with self.assertRaises(ValueError):
                    _derive_signing_kek(
                        password,
                        self.salt,
                    )

    def test_kek_invalid_salts(self):
        for salt in (
            None,
            "x" * 16,
            16,
            bytearray(16),
            memoryview(bytes(16)),
            b"",
            bytes(15),
            bytes(17),
        ):
            with self.subTest(
                input_type=type(salt).__name__
            ):
                with self.assertRaises(ValueError):
                    _derive_signing_kek(
                        self.password,
                        salt,
                    )

    def test_signing_context(self):
        from crypto_core import _encode_context
        from user_keys import _private_key_context

        expected = {
            "owner_id": 7,
            "kind": "signing_key",
            "item_id": "signing_key",
        }

        actual = _signing_key_context(7)

        self.assertEqual(actual, expected)

        self.assertEqual(
            _encode_context(actual),
            b'{"item_id":"signing_key","kind":"signing_key","owner_id":7}',
        )

        self.assertNotEqual(
            _encode_context(actual),
            _encode_context(
                _private_key_context(7)
            ),
        )

        self.assertNotEqual(
            _encode_context(actual),
            _encode_context(
                _signing_key_context(8)
            ),
        )

        for user_id in (
            None, True, False,
            0, -1, "7", 7.0,
        ):
            with self.subTest(user_id=user_id):
                with self.assertRaises(ValueError):
                    _signing_key_context(user_id)


# ============================================================
# Stage 5b: Existing signing-key generation tests
# ============================================================


class TestGenerateSigningKeypair(unittest.TestCase):

    USER_ID = 7
    USERNAME = "signing_test_user"
    PASSWORD = "Medimo-Test-密码"

    @classmethod
    def setUpClass(cls):
        cls.password_hash = generate_password_hash(
            cls.PASSWORD,
            method="scrypt:131072:8:1",
        )

        cls.changed_password_hash = generate_password_hash(
            cls.PASSWORD + "-changed",
            method="scrypt:131072:8:1",
        )

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)

        self.db_path = (
            Path(directory.name)
            / "test_signing_keys.db"
        )

        db_patcher = patch.object(
            db,
            "DB_PATH",
            self.db_path,
        )

        db_patcher.start()
        self.addCleanup(db_patcher.stop)

        db.init_db()

        self.execute(
            """
            INSERT INTO users (
                id,
                username,
                password_hash
            )
            VALUES (?, ?, ?)
            """,
            (
                self.USER_ID,
                self.USERNAME,
                self.password_hash,
            ),
        )

    def execute(self, sql, parameters=()):
        """Execute SQL in the temporary database only."""

        with closing(db.get_connection()) as connection:
            with connection:
                connection.execute(sql, parameters)

    def read_signing_row(self):
        with closing(db.get_connection()) as connection:
            return connection.execute(
                """
                SELECT *
                FROM signing_keys
                WHERE user_id = ?
                """,
                (self.USER_ID,),
            ).fetchone()

    def read_encryption_row(self):
        with closing(db.get_connection()) as connection:
            return connection.execute(
                """
                SELECT *
                FROM user_keys
                WHERE user_id = ?
                """,
                (self.USER_ID,),
            ).fetchone()

    def assert_no_signing_key(self):
        self.assertIsNone(
            self.read_signing_row()
        )

        with closing(db.get_connection()) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM signing_keys"
            ).fetchone()[0]

        self.assertEqual(count, 0)

    def generate(self):
        result = generate_signing_keypair(
            self.USER_ID,
            self.PASSWORD,
        )

        self.assertIsNone(result)

        row = self.read_signing_row()
        self.assertIsNotNone(row)

        return row

    def recover_private_der(self, row):
        context = {
            "owner_id": self.USER_ID,
            "kind": "signing_key",
            "item_id": "signing_key",
        }

        kek = _derive_signing_kek(
            self.PASSWORD,
            row["private_key_salt"],
        )

        return decrypt_blob(
            row["encrypted_private_key"],
            kek,
            "AES",
            context,
        )

    def test_successful_generation_and_initial_storage(self):
        row = self.generate()

        self.assertEqual(
            row["user_id"],
            self.USER_ID,
        )

        self.assertIsInstance(
            row["public_key_pem"],
            str,
        )

        self.assertTrue(
            row["public_key_pem"].startswith(
                "-----BEGIN PUBLIC KEY-----"
            )
        )

        public_key = RSA.import_key(
            row["public_key_pem"]
        )

        self.assertFalse(public_key.has_private())
        self.assertEqual(public_key.size_in_bits(), 3072)
        self.assertEqual(public_key.size_in_bytes(), 384)

        expected_hex = SHA256.new(
            public_key.export_key(format="DER")
        ).hexdigest().upper()

        expected_fingerprint = " ".join(
            expected_hex[i:i + 4]
            for i in range(0, 64, 4)
        )

        self.assertEqual(
            row["fingerprint"],
            expected_fingerprint,
        )

        self.assertEqual(len(row["fingerprint"]), 79)

        self.assertIsInstance(
            row["certificate_der"],
            bytes,
        )

        self.assertEqual(
            parse_der(row["certificate_der"]).raw,
            row["certificate_der"],
        )

        self.assertIsInstance(
            row["private_key_salt"],
            bytes,
        )

        self.assertEqual(
            len(row["private_key_salt"]),
            16,
        )

        self.assertIsInstance(
            row["encrypted_private_key"],
            bytes,
        )

        self.assertTrue(
            row["encrypted_private_key"].startswith(
                b"MDMO\x01\x01"
            )
        )

        self.assertEqual(
            row["failed_unlock_count"],
            0,
        )

        self.assertIsNone(row["locked_until"])
        self.assertIsNone(self.read_encryption_row())

        expected_columns = {
            "user_id",
            "public_key_pem",
            "fingerprint",
            "certificate_der",
            "private_key_salt",
            "encrypted_private_key",
            "failed_unlock_count",
            "locked_until",
            "expires_at",
            "created_at",
        }

        self.assertEqual(
            set(row.keys()),
            expected_columns,
        )

        with closing(db.get_connection()) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM signing_keys"
            ).fetchone()[0]

            audit_count = connection.execute(
                "SELECT COUNT(*) FROM signature_audit_log"
            ).fetchone()[0]

        self.assertEqual(count, 1)
        self.assertEqual(audit_count, 0)

    def test_certificate_consistency_and_self_signature(self):
        row = self.generate()

        parsed = parse_certificate(
            row["certificate_der"]
        )

        stored_key = RSA.import_key(
            row["public_key_pem"]
        )

        certificate_key = RSA.import_key(
            parsed["public_key_pem"]
        )

        self.assertEqual(
            (certificate_key.n, certificate_key.e),
            (stored_key.n, stored_key.e),
        )

        self.assertEqual(
            certificate_key.export_key(format="DER"),
            stored_key.export_key(format="DER"),
        )

        self.assertEqual(
            parsed["subject_cn"],
            self.USERNAME,
        )

        self.assertEqual(
            signing_public_key_fingerprint(
                parsed["public_key_pem"]
            ),
            row["fingerprint"],
        )

        self.assertTrue(
            rsa_verify(
                parsed["public_key_pem"],
                parsed["tbs_der"],
                parsed["signature"],
            )
        )

        pkcs1_15.new(
            certificate_key
        ).verify(
            SHA256.new(parsed["tbs_der"]),
            parsed["signature"],
        )

        created_at = datetime.fromisoformat(
            row["created_at"]
        )

        expires_at = datetime.fromisoformat(
            row["expires_at"]
        )

        self.assertEqual(
            created_at,
            parsed["not_before"],
        )

        self.assertEqual(
            expires_at,
            parsed["not_after"],
        )

        self.assertEqual(
            expires_at - created_at,
            timedelta(days=730),
        )

        for value in (created_at, expires_at):
            self.assertIsNotNone(value.tzinfo)
            self.assertEqual(value.utcoffset(), timedelta(0))
            self.assertEqual(value.microsecond, 0)

        self.assertTrue(
            row["created_at"].endswith("+00:00")
        )

        self.assertTrue(
            row["expires_at"].endswith("+00:00")
        )

    def test_recover_encrypted_pkcs8_private_key(self):
        row = self.generate()

        private_der = self.recover_private_der(row)

        self.assertIsInstance(private_der, bytes)

        fields = decode_value(
            parse_der(private_der),
            0x30,
        )

        self.assertEqual(
            [field.tag for field in fields],
            [0x02, 0x30, 0x04],
        )

        self.assertEqual(
            decode_value(fields[0], 0x02),
            0,
        )

        recovered = RSA.import_key(private_der)

        stored = RSA.import_key(
            row["public_key_pem"]
        )

        self.assertTrue(recovered.has_private())
        self.assertEqual(recovered.size_in_bits(), 3072)

        self.assertEqual(
            (recovered.n, recovered.e),
            (stored.n, stored.e),
        )

        self.assertEqual(
            recovered.public_key().export_key(format="DER"),
            stored.export_key(format="DER"),
        )

        self.assertNotEqual(
            private_der,
            row["encrypted_private_key"],
        )

        self.assertNotIn(
            private_der,
            row["encrypted_private_key"],
        )

        message = b"Recovered signing key test"

        signature = rsa_sign(
            recovered,
            message,
        )

        self.assertTrue(
            rsa_verify(
                row["public_key_pem"],
                message,
                signature,
            )
        )

    def test_wrong_kek_cannot_decrypt_private_key(self):
        row = self.generate()

        wrong_kek = _derive_signing_kek(
            self.PASSWORD + "-wrong",
            row["private_key_salt"],
        )

        with self.assertRaises(InvalidEnvelopeError):
            decrypt_blob(
                row["encrypted_private_key"],
                wrong_kek,
                "AES",
                _signing_key_context(self.USER_ID),
            )

        self.assertEqual(
            dict(self.read_signing_row()),
            dict(row),
        )

    def test_wrong_context_cannot_decrypt_private_key(self):
        row = self.generate()

        kek = _derive_signing_kek(
            self.PASSWORD,
            row["private_key_salt"],
        )

        wrong_contexts = (
            {
                "owner_id": self.USER_ID,
                "kind": "private_key",
                "item_id": "private_key",
            },
            {
                "owner_id": self.USER_ID + 1,
                "kind": "signing_key",
                "item_id": "signing_key",
            },
        )

        for context in wrong_contexts:
            with self.subTest(context=context):
                with self.assertRaises(InvalidEnvelopeError):
                    decrypt_blob(
                        row["encrypted_private_key"],
                        kek,
                        "AES",
                        context,
                    )

    def test_task2_key_and_lockout_state_remain_separate(self):
        generate_user_keypair(
            self.USER_ID,
            self.PASSWORD,
        )

        self.execute(
            """
            UPDATE user_keys
            SET failed_unlock_count = ?,
                locked_until = ?
            WHERE user_id = ?
            """,
            (
                5,
                "2099-01-01T00:00:00+00:00",
                self.USER_ID,
            ),
        )

        legacy_before = dict(
            self.read_encryption_row()
        )

        signing = self.generate()

        legacy_after = dict(
            self.read_encryption_row()
        )

        self.assertEqual(
            legacy_before,
            legacy_after,
        )

        encryption_key = RSA.import_key(
            legacy_before["public_key_pem"]
        )

        signing_key = RSA.import_key(
            signing["public_key_pem"]
        )

        self.assertEqual(encryption_key.size_in_bits(), 3072)
        self.assertEqual(signing_key.size_in_bits(), 3072)

        self.assertNotEqual(
            encryption_key.n,
            signing_key.n,
        )

        self.assertNotEqual(
            legacy_before["fingerprint"],
            signing["fingerprint"],
        )

        self.assertNotEqual(
            legacy_before["private_key_salt"],
            signing["private_key_salt"],
        )

        self.assertNotEqual(
            legacy_before["encrypted_private_key"],
            signing["encrypted_private_key"],
        )

        legacy_kek = _derive_signing_kek(
            self.PASSWORD,
            legacy_before["private_key_salt"],
        )

        signing_kek = _derive_signing_kek(
            self.PASSWORD,
            signing["private_key_salt"],
        )

        self.assertNotEqual(legacy_kek, signing_kek)

        with self.assertRaises(InvalidEnvelopeError):
            decrypt_blob(
                signing["encrypted_private_key"],
                legacy_kek,
                "AES",
                _signing_key_context(self.USER_ID),
            )

        self.assertEqual(
            legacy_after["failed_unlock_count"],
            5,
        )

        self.assertEqual(
            legacy_after["locked_until"],
            "2099-01-01T00:00:00+00:00",
        )

        self.assertEqual(
            signing["failed_unlock_count"],
            0,
        )

        self.assertIsNone(signing["locked_until"])

    def test_wrong_and_invalid_passwords_rejected(self):
        passwords = (
            "wrong-password",
            "",
            None,
            123,
            True,
            b"password",
            "\ud800",
        )

        with patch(
            "signing_keys.RSA.generate",
            side_effect=AssertionError(
                "RSA generation must not be reached"
            ),
        ) as generation:

            for password in passwords:
                with self.subTest(
                    password_type=type(password).__name__
                ):
                    with self.assertRaises(KeyUnlockError):
                        generate_signing_keypair(
                            self.USER_ID,
                            password,
                        )

            generation.assert_not_called()

        self.assert_no_signing_key()

    def test_invalid_and_nonexistent_user_ids(self):
        values = (
            None, True, False,
            0, -1, "7", 7.0, b"7",
            999999,
            1 << 63,
        )

        with patch(
            "signing_keys.RSA.generate",
            side_effect=AssertionError(
                "RSA generation must not be reached"
            ),
        ) as generation:

            for user_id in values:
                with self.subTest(user_id=user_id):
                    with self.assertRaises(ValueError):
                        generate_signing_keypair(
                            user_id,
                            self.PASSWORD,
                        )

            generation.assert_not_called()

        self.assert_no_signing_key()

    def test_duplicate_signing_key_generation_rejected(self):
        original = dict(self.generate())

        with patch(
            "signing_keys.RSA.generate",
            side_effect=AssertionError(
                "Existing key must not be regenerated"
            ),
        ) as generation:

            with self.assertRaisesRegex(
                ValueError,
                "already has a signing keypair",
            ):
                generate_signing_keypair(
                    self.USER_ID,
                    self.PASSWORD,
                )

            generation.assert_not_called()

        self.assertEqual(
            dict(self.read_signing_row()),
            original,
        )

    def test_concurrent_duplicate_created_during_generation(self):
        competitor = dict(self.generate())

        self.execute(
            """
            DELETE FROM signing_keys
            WHERE user_id = ?
            """,
            (self.USER_ID,),
        )

        def concurrent_insert_then_build(
            private_key,
            username,
            not_before,
            not_after,
        ):
            self.execute(
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
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    competitor["user_id"],
                    competitor["public_key_pem"],
                    competitor["fingerprint"],
                    competitor["certificate_der"],
                    competitor["private_key_salt"],
                    competitor["encrypted_private_key"],
                    competitor["failed_unlock_count"],
                    competitor["locked_until"],
                    competitor["expires_at"],
                    competitor["created_at"],
                ),
            )

            return build_self_signed_certificate(
                private_key,
                username,
                not_before,
                not_after,
            )

        with patch(
            "signing_keys.build_self_signed_certificate",
            side_effect=concurrent_insert_then_build,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "already has a signing keypair",
            ):
                generate_signing_keypair(
                    self.USER_ID,
                    self.PASSWORD,
                )

        self.assertEqual(
            dict(self.read_signing_row()),
            competitor,
        )

    def test_password_hash_changes_during_generation(self):
        def change_password_then_build(
            private_key,
            username,
            not_before,
            not_after,
        ):
            self.execute(
                """
                UPDATE users
                SET password_hash = ?
                WHERE id = ?
                """,
                (
                    self.changed_password_hash,
                    self.USER_ID,
                ),
            )

            return build_self_signed_certificate(
                private_key,
                username,
                not_before,
                not_after,
            )

        with patch(
            "signing_keys.build_self_signed_certificate",
            side_effect=change_password_then_build,
        ):
            with self.assertRaises(KeyUnlockError):
                generate_signing_keypair(
                    self.USER_ID,
                    self.PASSWORD,
                )

        self.assert_no_signing_key()

        with closing(db.get_connection()) as connection:
            user = connection.execute(
                """
                SELECT password_hash
                FROM users
                WHERE id = ?
                """,
                (self.USER_ID,),
            ).fetchone()

        self.assertEqual(
            user["password_hash"],
            self.changed_password_hash,
        )

    def test_user_deleted_during_generation(self):
        def delete_user_then_build(
            private_key,
            username,
            not_before,
            not_after,
        ):
            self.execute(
                """
                DELETE FROM users
                WHERE id = ?
                """,
                (self.USER_ID,),
            )

            return build_self_signed_certificate(
                private_key,
                username,
                not_before,
                not_after,
            )

        with patch(
            "signing_keys.build_self_signed_certificate",
            side_effect=delete_user_then_build,
        ):
            with self.assertRaises(KeyUnlockError):
                generate_signing_keypair(
                    self.USER_ID,
                    self.PASSWORD,
                )

        self.assert_no_signing_key()

        with closing(db.get_connection()) as connection:
            user = connection.execute(
                """
                SELECT id
                FROM users
                WHERE id = ?
                """,
                (self.USER_ID,),
            ).fetchone()

        self.assertIsNone(user)

    def test_username_changes_during_generation(self):
        def change_username_then_build(
            private_key,
            username,
            not_before,
            not_after,
        ):
            self.execute(
                """
                UPDATE users
                SET username = ?
                WHERE id = ?
                """,
                (
                    "renamed_signing_user",
                    self.USER_ID,
                ),
            )

            return build_self_signed_certificate(
                private_key,
                username,
                not_before,
                not_after,
            )

        with patch(
            "signing_keys.build_self_signed_certificate",
            side_effect=change_username_then_build,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "username changed",
            ):
                generate_signing_keypair(
                    self.USER_ID,
                    self.PASSWORD,
                )

        self.assert_no_signing_key()

    def test_certificate_generation_failure_no_partial_key(self):
        with patch(
            "signing_keys.build_self_signed_certificate",
            side_effect=RuntimeError(
                "Injected certificate generation failure"
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "Injected certificate",
            ):
                generate_signing_keypair(
                    self.USER_ID,
                    self.PASSWORD,
                )

        self.assert_no_signing_key()

    def test_encryption_failure_no_partial_key(self):
        with patch(
            "signing_keys.encrypt_blob",
            side_effect=RuntimeError(
                "Injected encryption failure"
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "Injected encryption failure",
            ):
                generate_signing_keypair(
                    self.USER_ID,
                    self.PASSWORD,
                )

        self.assert_no_signing_key()

    def test_database_insert_failure_rolls_back(self):
        self.execute(
            """
            CREATE TRIGGER test_fail_signing_insert
            AFTER INSERT ON signing_keys
            BEGIN
                SELECT RAISE(
                    FAIL,
                    'Injected signing insert failure'
                );
            END
            """
        )

        with self.assertRaisesRegex(
            sqlite3.IntegrityError,
            "Injected signing insert failure",
        ):
            generate_signing_keypair(
                self.USER_ID,
                self.PASSWORD,
            )

        self.assert_no_signing_key()

        self.execute(
            "DROP TRIGGER test_fail_signing_insert"
        )

        row = self.generate()

        self.assertEqual(
            row["user_id"],
            self.USER_ID,
        )

    def test_certificate_public_key_mismatch_rejected(self):
        other_private_key = RSA.generate(3072)

        def build_with_other_key(
            private_key,
            username,
            not_before,
            not_after,
        ):
            self.assertNotEqual(
                private_key.n,
                other_private_key.n,
            )

            return build_self_signed_certificate(
                other_private_key,
                username,
                not_before,
                not_after,
            )

        with patch(
            "signing_keys.build_self_signed_certificate",
            side_effect=build_with_other_key,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "certificate public key mismatch",
            ):
                generate_signing_keypair(
                    self.USER_ID,
                    self.PASSWORD,
                )

        self.assert_no_signing_key()

    def test_invalid_certificate_self_signature_rejected(self):
        def build_tampered_certificate(
            private_key,
            username,
            not_before,
            not_after,
        ):
            certificate = build_self_signed_certificate(
                private_key,
                username,
                not_before,
                not_after,
            )

            modified = (
                certificate[:-1]
                + bytes([certificate[-1] ^ 1])
            )

            parsed = parse_certificate(modified)

            self.assertFalse(
                rsa_verify(
                    parsed["public_key_pem"],
                    parsed["tbs_der"],
                    parsed["signature"],
                )
            )

            return modified

        with patch(
            "signing_keys.build_self_signed_certificate",
            side_effect=build_tampered_certificate,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "self-signature is invalid",
            ):
                generate_signing_keypair(
                    self.USER_ID,
                    self.PASSWORD,
                )

        self.assert_no_signing_key()

    def test_primary_key_constraint_failure_is_duplicate_error(self):
        self.execute(
            """
            CREATE TRIGGER test_signing_pk_collision
            BEFORE INSERT ON signing_keys
            WHEN NEW.failed_unlock_count = 0
            BEGIN
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
                VALUES (
                    NEW.user_id,
                    NEW.public_key_pem,
                    'TEST-COLLISION-FINGERPRINT',
                    NEW.certificate_der,
                    NEW.private_key_salt,
                    NEW.encrypted_private_key,
                    1,
                    NULL,
                    NEW.expires_at,
                    NEW.created_at
                );
            END
            """
        )

        with self.assertRaisesRegex(
            ValueError,
            "already has a signing keypair",
        ):
            generate_signing_keypair(
                self.USER_ID,
                self.PASSWORD,
            )

        self.assert_no_signing_key()

    def test_leap_year_timestamp_and_immediate_signing(self):
        generation_time = datetime(
            2028, 2, 29,
            23, 59, 59, 987654,
            tzinfo=timezone.utc,
        )

        expected_start = datetime(
            2028, 2, 29,
            23, 59, 59,
            tzinfo=timezone.utc,
        )

        expected_end = datetime(
            2030, 2, 28,
            23, 59, 59,
            tzinfo=timezone.utc,
        )

        with patch(
            "signing_keys._signing_utc_now",
            return_value=generation_time,
        ) as clock:

            row = self.generate()

        clock.assert_called_once_with()

        parsed = parse_certificate(
            row["certificate_der"]
        )

        self.assertEqual(
            parsed["not_before"],
            expected_start,
        )

        self.assertEqual(
            parsed["not_after"],
            expected_end,
        )

        self.assertEqual(
            parsed["not_after"] - parsed["not_before"],
            timedelta(days=730),
        )

        self.assertEqual(
            row["created_at"],
            "2028-02-29T23:59:59+00:00",
        )

        self.assertEqual(
            row["expires_at"],
            "2030-02-28T23:59:59+00:00",
        )

        immediate_signing_time = generation_time.replace(
            microsecond=0
        )

        self.assertTrue(
            parsed["not_before"]
            <= immediate_signing_time
            <= parsed["not_after"]
        )

        recovered = RSA.import_key(
            self.recover_private_der(row)
        )

        message = b"Immediate signing after key generation"

        signature = rsa_sign(
            recovered,
            message,
        )

        self.assertTrue(
            rsa_verify(
                row["public_key_pem"],
                message,
                signature,
            )
        )


# ============================================================
# Stage 5c: Public retrieval and signer lookup tests
# ============================================================


class TestSigningKeyRetrieval(unittest.TestCase):

    USER_ID = 7
    USERNAME = "signing_test_user"

    EXPIRED_USER_ID = 8
    EXPIRED_USERNAME = "expired_signing_user"

    TASK2_USER_ID = 9
    TASK2_USERNAME = "encryption_only_user"

    PASSWORD = "Medimo-Retrieval-Test"

    @classmethod
    def setUpClass(cls):
        """Create real cryptographic fixtures only once."""

        directory = tempfile.TemporaryDirectory()

        cls.addClassCleanup(directory.cleanup)

        cls.seed_path = (
            Path(directory.name)
            / "seed_signing_keys.db"
        )

        password_hash = generate_password_hash(
            cls.PASSWORD,
            method="scrypt:131072:8:1",
        )

        with patch.object(
            db,
            "DB_PATH",
            cls.seed_path,
        ):
            db.init_db()

            with closing(db.get_connection()) as connection:
                with connection:
                    connection.executemany(
                        """
                        INSERT INTO users (
                            id,
                            username,
                            password_hash
                        )
                        VALUES (?, ?, ?)
                        """,
                        (
                            (
                                cls.USER_ID,
                                cls.USERNAME,
                                password_hash,
                            ),
                            (
                                cls.EXPIRED_USER_ID,
                                cls.EXPIRED_USERNAME,
                                password_hash,
                            ),
                            (
                                cls.TASK2_USER_ID,
                                cls.TASK2_USERNAME,
                                password_hash,
                            ),
                        ),
                    )

            generate_signing_keypair(
                cls.USER_ID,
                cls.PASSWORD,
            )

            # Generate an actual historical certificate,
            # rather than altering only expires_at.
            with patch(
                "signing_keys._signing_utc_now",
                return_value=datetime(
                    2000, 1, 1,
                    tzinfo=timezone.utc,
                ),
            ):
                generate_signing_keypair(
                    cls.EXPIRED_USER_ID,
                    cls.PASSWORD,
                )

            generate_user_keypair(
                cls.TASK2_USER_ID,
                cls.PASSWORD,
            )

            with closing(db.get_connection()) as connection:
                cls.first_row = dict(
                    connection.execute(
                        """
                        SELECT *
                        FROM signing_keys
                        WHERE user_id = ?
                        """,
                        (cls.USER_ID,),
                    ).fetchone()
                )

                cls.expired_row = dict(
                    connection.execute(
                        """
                        SELECT *
                        FROM signing_keys
                        WHERE user_id = ?
                        """,
                        (cls.EXPIRED_USER_ID,),
                    ).fetchone()
                )

                cls.task2_row = dict(
                    connection.execute(
                        """
                        SELECT *
                        FROM user_keys
                        WHERE user_id = ?
                        """,
                        (cls.TASK2_USER_ID,),
                    ).fetchone()
                )

        cls.fingerprint = cls.first_row["fingerprint"]
        cls.expired_fingerprint = cls.expired_row["fingerprint"]
        cls.task2_fingerprint = cls.task2_row["fingerprint"]

        cls.unknown_fingerprint = next(
            candidate
            for candidate in (
                " ".join([f"{number:04X}"] * 16)
                for number in range(65536)
            )
            if candidate not in {
                cls.fingerprint,
                cls.expired_fingerprint,
                cls.task2_fingerprint,
            }
        )

    def setUp(self):
        """Each test receives an independent copy of the seed DB."""

        directory = tempfile.TemporaryDirectory()

        self.addCleanup(directory.cleanup)

        self.db_path = (
            Path(directory.name)
            / "test_retrieval.db"
        )

        with closing(
            sqlite3.connect(self.seed_path)
        ) as source:

            with closing(
                sqlite3.connect(self.db_path)
            ) as destination:

                source.backup(destination)

        db_patcher = patch.object(
            db,
            "DB_PATH",
            self.db_path,
        )

        db_patcher.start()
        self.addCleanup(db_patcher.stop)

    def execute(self, sql, parameters=()):
        with closing(db.get_connection()) as connection:
            with connection:
                connection.execute(sql, parameters)

    def public_fields(self, row):
        return {
            "public_key_pem": row["public_key_pem"],
            "fingerprint": row["fingerprint"],
            "certificate_der": row["certificate_der"],
            "expires_at": row["expires_at"],
        }

    def snapshot(self):
        """Capture relevant database state for read-only tests."""

        queries = (
            (
                "users",
                "SELECT * FROM users ORDER BY id",
            ),
            (
                "signing_keys",
                "SELECT * FROM signing_keys ORDER BY user_id",
            ),
            (
                "user_keys",
                "SELECT * FROM user_keys ORDER BY user_id",
            ),
            (
                "signature_audit_log",
                "SELECT * FROM signature_audit_log ORDER BY id",
            ),
            (
                "document_signatures",
                "SELECT * FROM document_signatures ORDER BY id",
            ),
        )

        with closing(db.get_connection()) as connection:
            return {
                name: [
                    dict(row)
                    for row in connection.execute(sql).fetchall()
                ]
                for name, sql in queries
            }

    # ========================================================
    # get_signing_key
    # ========================================================

    def test_get_signing_key_exact_fields_and_types(self):
        result = get_signing_key(self.USER_ID)

        self.assertIs(type(result), dict)

        expected_types = {
            "public_key_pem": str,
            "fingerprint": str,
            "certificate_der": bytes,
            "expires_at": str,
        }

        self.assertEqual(
            set(result),
            set(expected_types),
        )

        for name, expected_type in expected_types.items():
            with self.subTest(field=name):
                self.assertIs(
                    type(result[name]),
                    expected_type,
                )

        self.assertEqual(
            result,
            self.public_fields(self.first_row),
        )

        self.assertTrue(
            result["public_key_pem"].startswith(
                "-----BEGIN PUBLIC KEY-----"
            )
        )

        self.assertEqual(
            signing_public_key_fingerprint(
                result["public_key_pem"]
            ),
            result["fingerprint"],
        )

        parsed = parse_certificate(
            result["certificate_der"]
        )

        expires_at = datetime.fromisoformat(
            result["expires_at"]
        )

        self.assertEqual(
            expires_at,
            parsed["not_after"],
        )

        self.assertEqual(
            expires_at.utcoffset(),
            timedelta(0),
        )

        self.assertTrue(
            result["expires_at"].endswith("+00:00")
        )

    def test_get_signing_key_preserves_raw_certificate(self):
        expected = self.first_row["certificate_der"]

        actual = get_signing_key(
            self.USER_ID
        )["certificate_der"]

        self.assertIs(type(actual), bytes)
        self.assertEqual(actual, expected)

        self.assertEqual(
            parse_der(actual).raw,
            expected,
        )

    def test_get_signing_key_missing_and_nonexistent(self):
        # Existing account with a Task 2 key, but no signing key.
        self.assertIsNone(
            get_signing_key(self.TASK2_USER_ID)
        )

        # Valid user ID that is absent from the database.
        self.assertIsNone(
            get_signing_key(999999)
        )

        # Largest representable SQLite INTEGER.
        self.assertIsNone(
            get_signing_key((1 << 63) - 1)
        )

    def test_get_signing_key_invalid_user_ids(self):
        values = (
            None,
            True,
            False,
            0,
            -1,
            "7",
            b"7",
            7.0,
            object(),
            1 << 63,
            10**100,
            "7 OR 1=1",
        )

        with patch(
            "signing_keys.get_connection",
            side_effect=AssertionError(
                "Invalid input must not reach the database"
            ),
        ) as connection_factory:

            for user_id in values:
                with self.subTest(user_id=user_id):
                    with self.assertRaises(ValueError):
                        get_signing_key(user_id)

            connection_factory.assert_not_called()

    def test_expired_signing_key_remains_retrievable(self):
        result = get_signing_key(
            self.EXPIRED_USER_ID
        )

        self.assertEqual(
            result,
            self.public_fields(self.expired_row),
        )

        parsed = parse_certificate(
            result["certificate_der"]
        )

        expires_at = datetime.fromisoformat(
            result["expires_at"]
        )

        self.assertEqual(
            expires_at,
            parsed["not_after"],
        )

        self.assertLess(
            expires_at,
            datetime.now(timezone.utc),
        )

        self.assertTrue(
            rsa_verify(
                parsed["public_key_pem"],
                parsed["tbs_der"],
                parsed["signature"],
            )
        )

    def test_locked_signing_key_remains_retrievable(self):
        locked_until = (
            datetime.now(timezone.utc)
            + timedelta(minutes=15)
        ).isoformat()

        self.execute(
            """
            UPDATE signing_keys
            SET failed_unlock_count = 5,
                locked_until = ?
            WHERE user_id = ?
            """,
            (locked_until, self.USER_ID),
        )

        before = self.snapshot()

        result = get_signing_key(
            self.USER_ID
        )

        self.assertEqual(
            result,
            self.public_fields(self.first_row),
        )

        self.assertNotIn(
            "failed_unlock_count",
            result,
        )

        self.assertNotIn(
            "locked_until",
            result,
        )

        self.assertEqual(
            self.snapshot(),
            before,
        )

    def test_public_reads_do_not_use_cryptographic_operations(self):
        forbidden_calls = (
            "signing_keys._derive_signing_kek",
            "signing_keys.scrypt",
            "signing_keys.encrypt_blob",
            "crypto_core.decrypt_blob",
            "signing_keys.check_password_hash",
            "signing_keys.RSA.generate",
            "signing_keys.RSA.import_key",
            "signing_keys.rsa_verify",
            "signing_keys.rsa_sign",
            "signing_keys.parse_certificate",
            "signing_keys.signing_public_key_fingerprint",
        )

        with ExitStack() as stack:
            mocks = [
                stack.enter_context(
                    patch(
                        name,
                        side_effect=AssertionError(
                            f"Unexpected public-read operation: {name}"
                        ),
                    )
                )
                for name in forbidden_calls
            ]

            self.assertEqual(
                get_signing_key(self.USER_ID),
                self.public_fields(self.first_row),
            )

            self.assertEqual(
                find_signer_by_fingerprint(
                    self.fingerprint
                ),
                {
                    "user_id": self.USER_ID,
                    "username": self.USERNAME,
                },
            )

            self.assertIsNone(
                get_signing_key(self.TASK2_USER_ID)
            )

            self.assertIsNone(
                find_signer_by_fingerprint(
                    self.unknown_fingerprint
                )
            )

            for mocked in mocks:
                mocked.assert_not_called()

    def test_public_reads_do_not_change_database_state(self):
        before = self.snapshot()

        for _ in range(3):
            get_signing_key(self.USER_ID)
            get_signing_key(self.EXPIRED_USER_ID)
            get_signing_key(self.TASK2_USER_ID)
            get_signing_key(999999)

            find_signer_by_fingerprint(
                self.fingerprint
            )

            find_signer_by_fingerprint(
                self.expired_fingerprint
            )

            find_signer_by_fingerprint(
                self.task2_fingerprint
            )

            find_signer_by_fingerprint(
                self.unknown_fingerprint
            )

        after = self.snapshot()

        self.assertEqual(after, before)

        self.assertEqual(
            len(after["signature_audit_log"]),
            0,
        )

    # ========================================================
    # find_signer_by_fingerprint
    # ========================================================

    def test_find_signer_exact_fields_and_types(self):
        result = find_signer_by_fingerprint(
            self.fingerprint
        )

        self.assertIs(type(result), dict)

        self.assertEqual(
            set(result),
            {"user_id", "username"},
        )

        self.assertIs(
            type(result["user_id"]),
            int,
        )

        self.assertIs(
            type(result["username"]),
            str,
        )

        self.assertEqual(
            result,
            {
                "user_id": self.USER_ID,
                "username": self.USERNAME,
            },
        )

    def test_unknown_fingerprint_returns_none(self):
        self.assertRegex(
            self.unknown_fingerprint,
            r"\A[0-9A-F]{4}( [0-9A-F]{4}){15}\Z",
        )

        self.assertIsNone(
            find_signer_by_fingerprint(
                self.unknown_fingerprint
            )
        )

    def test_invalid_fingerprint_inputs(self):
        canonical = " ".join(["ABCD"] * 16)

        values = (
            None,
            True,
            False,
            123,
            object(),
            canonical.encode("ascii"),
            bytearray(canonical.encode("ascii")),
            "",
            " ",
            "ABCD",
            canonical.lower(),
            canonical.replace(" ", ""),
            canonical.replace(" ", "  ", 1),
            canonical.replace(" ", "\t", 1),
            canonical.replace(" ", "\n", 1),
            " " + canonical,
            canonical + " ",
            canonical + "\n",
            canonical[:-1],
            canonical + "A",
            "G" + canonical[1:],
            "Ａ" + canonical[1:],
            "'" + canonical[1:],
            "' OR 1=1 --",
            "\x00" + canonical[1:],
            "A" * 10000,
        )

        with patch(
            "signing_keys.get_connection",
            side_effect=AssertionError(
                "Malformed fingerprint must not reach the database"
            ),
        ) as connection_factory:

            for index, value in enumerate(values):
                with self.subTest(case=index):
                    with self.assertRaises(ValueError):
                        find_signer_by_fingerprint(value)

            connection_factory.assert_not_called()

    def test_fingerprint_lookup_multiple_users(self):
        cases = (
            (
                self.fingerprint,
                self.USER_ID,
                self.USERNAME,
            ),
            (
                self.expired_fingerprint,
                self.EXPIRED_USER_ID,
                self.EXPIRED_USERNAME,
            ),
        )

        self.assertNotEqual(
            self.fingerprint,
            self.expired_fingerprint,
        )

        for fingerprint, user_id, username in cases:
            with self.subTest(user_id=user_id):
                self.assertEqual(
                    find_signer_by_fingerprint(
                        fingerprint
                    ),
                    {
                        "user_id": user_id,
                        "username": username,
                    },
                )

    def test_task2_fingerprint_not_found_by_signing_lookup(self):
        self.assertEqual(
            public_key_fingerprint(
                self.task2_row["public_key_pem"]
            ),
            self.task2_fingerprint,
        )

        # The fingerprint algorithm is compatible,
        # but the storage domain is separate.
        self.assertEqual(
            signing_public_key_fingerprint(
                self.task2_row["public_key_pem"]
            ),
            self.task2_fingerprint,
        )

        self.assertNotIn(
            self.task2_fingerprint,
            (
                self.fingerprint,
                self.expired_fingerprint,
            ),
        )

        self.assertIsNone(
            find_signer_by_fingerprint(
                self.task2_fingerprint
            )
        )

        self.assertIsNone(
            get_signing_key(self.TASK2_USER_ID)
        )

    def test_lookup_uses_current_database_username(self):
        certificate = parse_certificate(
            self.first_row["certificate_der"]
        )

        self.assertEqual(
            certificate["subject_cn"],
            self.USERNAME,
        )

        new_username = "renamed_registered_user"

        self.execute(
            """
            UPDATE users
            SET username = ?
            WHERE id = ?
            """,
            (new_username, self.USER_ID),
        )

        signer = find_signer_by_fingerprint(
            self.fingerprint
        )

        self.assertEqual(
            signer,
            {
                "user_id": self.USER_ID,
                "username": new_username,
            },
        )

        self.assertNotEqual(
            signer["username"],
            certificate["subject_cn"],
        )

        self.assertEqual(
            get_signing_key(
                self.USER_ID
            )["certificate_der"],
            self.first_row["certificate_der"],
        )

    def test_lookup_expired_signing_certificate(self):
        expires_at = datetime.fromisoformat(
            self.expired_row["expires_at"]
        )

        self.assertLess(
            expires_at,
            datetime.now(timezone.utc),
        )

        result = find_signer_by_fingerprint(
            self.expired_fingerprint
        )

        self.assertEqual(
            result,
            {
                "user_id": self.EXPIRED_USER_ID,
                "username": self.EXPIRED_USERNAME,
            },
        )

    # ========================================================
    # SQL safety and database connection lifecycle
    # ========================================================

    def test_parameterized_queries_and_public_columns_only(self):
        class TrackingConnection(sqlite3.Connection):

            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.calls = []

            def execute(self, sql, parameters=()):
                self.calls.append(
                    (sql, tuple(parameters))
                )

                return super().execute(
                    sql,
                    parameters,
                )

        cases = (
            (
                get_signing_key,
                self.USER_ID,
                self.public_fields(self.first_row),
                {
                    ("signing_keys", "user_id"),
                    ("signing_keys", "public_key_pem"),
                    ("signing_keys", "fingerprint"),
                    ("signing_keys", "certificate_der"),
                    ("signing_keys", "expires_at"),
                },
            ),
            (
                find_signer_by_fingerprint,
                self.fingerprint,
                {
                    "user_id": self.USER_ID,
                    "username": self.USERNAME,
                },
                {
                    ("signing_keys", "user_id"),
                    ("signing_keys", "fingerprint"),
                    ("users", "id"),
                    ("users", "username"),
                },
            ),
        )

        for function, argument, expected, allowed in cases:
            with self.subTest(
                function=function.__name__
            ):
                connection = sqlite3.connect(
                    self.db_path,
                    factory=TrackingConnection,
                )

                self.addCleanup(connection.close)

                connection.row_factory = sqlite3.Row

                def authorizer(
                    action, table, column, database, source
                ):
                    if action == sqlite3.SQLITE_SELECT:
                        return sqlite3.SQLITE_OK

                    if action == sqlite3.SQLITE_READ:
                        if (table, column) in allowed:
                            return sqlite3.SQLITE_OK

                    # Reject unrelated columns and all writes.
                    return sqlite3.SQLITE_DENY

                connection.set_authorizer(authorizer)

                with patch(
                    "signing_keys.get_connection",
                    return_value=connection,
                ):
                    result = function(argument)

                self.assertEqual(result, expected)

                self.assertEqual(
                    len(connection.calls),
                    1,
                )

                sql, parameters = connection.calls[0]

                self.assertIn("?", sql)

                self.assertEqual(
                    parameters,
                    (argument,),
                )

                self.assertNotIn(
                    "SELECT *",
                    " ".join(sql.upper().split()),
                )

                with self.assertRaises(
                    sqlite3.ProgrammingError
                ):
                    connection.execute("SELECT 1")

    def test_database_failure_propagates_and_closes_connection(self):
        # A real SQLite error: required table is missing.
        self.execute(
            "DROP TABLE signing_keys"
        )

        cases = (
            (get_signing_key, self.USER_ID),
            (
                find_signer_by_fingerprint,
                self.fingerprint,
            ),
        )

        for function, argument in cases:
            with self.subTest(
                function=function.__name__
            ):
                connection = db.get_connection()

                self.addCleanup(connection.close)

                with patch(
                    "signing_keys.get_connection",
                    return_value=connection,
                ):
                    with self.assertRaisesRegex(
                        sqlite3.OperationalError,
                        "no such table",
                    ):
                        function(argument)

                # Connection must be closed even if SELECT failed.
                with self.assertRaises(
                    sqlite3.ProgrammingError
                ):
                    connection.execute("SELECT 1")

    def test_connection_cleanup_on_success_and_missing_record(self):
        cases = (
            (
                get_signing_key,
                self.USER_ID,
                self.public_fields(self.first_row),
            ),
            (
                get_signing_key,
                self.TASK2_USER_ID,
                None,
            ),
            (
                find_signer_by_fingerprint,
                self.fingerprint,
                {
                    "user_id": self.USER_ID,
                    "username": self.USERNAME,
                },
            ),
            (
                find_signer_by_fingerprint,
                self.unknown_fingerprint,
                None,
            ),
        )

        for function, argument, expected in cases:
            with self.subTest(
                function=function.__name__,
                found=expected is not None,
            ):
                connection = db.get_connection()

                self.addCleanup(connection.close)

                with patch(
                    "signing_keys.get_connection",
                    return_value=connection,
                ) as factory:

                    result = function(argument)

                factory.assert_called_once_with()

                self.assertEqual(
                    result,
                    expected,
                )

                with self.assertRaises(
                    sqlite3.ProgrammingError
                ):
                    connection.execute("SELECT 1")

    def test_database_connection_failure_propagates(self):
        cases = (
            (get_signing_key, self.USER_ID),
            (
                find_signer_by_fingerprint,
                self.fingerprint,
            ),
        )

        for function, argument in cases:
            with self.subTest(
                function=function.__name__
            ):
                with patch(
                    "signing_keys.get_connection",
                    side_effect=sqlite3.OperationalError(
                        "Injected database connection failure"
                    ),
                ):
                    with self.assertRaisesRegex(
                        sqlite3.OperationalError,
                        "Injected database connection failure",
                    ):
                        function(argument)


# ============================================================
# Stage 6: Complete signing-key unlock and security tests
# ============================================================


class TestUnlockSigningKey(unittest.TestCase):

    USER_ID = 7
    USERNAME = "unlock_signing_test_user"

    EMPTY_USER_ID = 8

    PASSWORD = "Medimo-Unlock-密码"
    WRONG_PASSWORD = "Incorrect-Password"

    NOW = datetime(
        2026, 11, 28,
        12, 0, 0,
        tzinfo=timezone.utc,
    )

    @classmethod
    def setUpClass(cls):
        """Generate real cryptographic fixtures once."""

        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)

        cls.seed_path = (
            Path(directory.name)
            / "seed_unlock_signing.db"
        )

        password_hash = generate_password_hash(
            cls.PASSWORD,
            method="scrypt:131072:8:1",
        )

        with patch.object(
            db,
            "DB_PATH",
            cls.seed_path,
        ):
            db.init_db()

            with closing(db.get_connection()) as connection:
                with connection:
                    connection.executemany(
                        """
                        INSERT INTO users (
                            id,
                            username,
                            password_hash
                        )
                        VALUES (?, ?, ?)
                        """,
                        (
                            (
                                cls.USER_ID,
                                cls.USERNAME,
                                password_hash,
                            ),
                            (
                                cls.EMPTY_USER_ID,
                                "no_signing_key_user",
                                password_hash,
                            ),
                        ),
                    )

            with patch(
                "signing_keys._signing_utc_now",
                return_value=cls.NOW,
            ):
                generate_signing_keypair(
                    cls.USER_ID,
                    cls.PASSWORD,
                )

            generate_user_keypair(
                cls.USER_ID,
                cls.PASSWORD,
            )

            with closing(db.get_connection()) as connection:
                cls.signing_row = dict(
                    connection.execute(
                        """
                        SELECT *
                        FROM signing_keys
                        WHERE user_id = ?
                        """,
                        (cls.USER_ID,),
                    ).fetchone()
                )

                cls.encryption_row = dict(
                    connection.execute(
                        """
                        SELECT *
                        FROM user_keys
                        WHERE user_id = ?
                        """,
                        (cls.USER_ID,),
                    ).fetchone()
                )

        cls.signing_context = {
            "owner_id": cls.USER_ID,
            "kind": "signing_key",
            "item_id": "signing_key",
        }

        cls.encryption_context = {
            "owner_id": cls.USER_ID,
            "kind": "private_key",
            "item_id": "private_key",
        }

        # Recover the original test keys independently from
        # unlock_signing_key, which is the function under test.
        signing_kek = _derive_signing_kek(
            cls.PASSWORD,
            cls.signing_row["private_key_salt"],
        )

        encryption_kek = _derive_signing_kek(
            cls.PASSWORD,
            cls.encryption_row["private_key_salt"],
        )

        cls.original_private = RSA.import_key(
            decrypt_blob(
                cls.signing_row["encrypted_private_key"],
                signing_kek,
                "AES",
                cls.signing_context,
            )
        )

        cls.encryption_private = RSA.import_key(
            decrypt_blob(
                cls.encryption_row["encrypted_private_key"],
                encryption_kek,
                "AES",
                cls.encryption_context,
            )
        )

        del signing_kek
        del encryption_kek

    def setUp(self):
        """Give each test an independent database copy."""

        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)

        self.db_path = (
            Path(directory.name)
            / "test_unlock_signing.db"
        )

        with closing(
            sqlite3.connect(self.seed_path)
        ) as source:
            with closing(
                sqlite3.connect(self.db_path)
            ) as destination:
                source.backup(destination)

        db_patcher = patch.object(
            db,
            "DB_PATH",
            self.db_path,
        )

        db_patcher.start()
        self.addCleanup(db_patcher.stop)

        clock_patcher = patch(
            "signing_keys._signing_utc_now",
            return_value=self.NOW,
        )

        self.clock = clock_patcher.start()
        self.addCleanup(clock_patcher.stop)

    # ========================================================
    # Database and cryptographic fixture helpers
    # ========================================================

    def execute(self, sql, parameters=()):
        with closing(db.get_connection()) as connection:
            with connection:
                connection.execute(
                    sql,
                    parameters,
                )

    def read_signing_row(self):
        with closing(db.get_connection()) as connection:
            row = connection.execute(
                """
                SELECT *
                FROM signing_keys
                WHERE user_id = ?
                """,
                (self.USER_ID,),
            ).fetchone()

        return None if row is None else dict(row)

    def read_encryption_row(self):
        with closing(db.get_connection()) as connection:
            row = connection.execute(
                """
                SELECT *
                FROM user_keys
                WHERE user_id = ?
                """,
                (self.USER_ID,),
            ).fetchone()

        return None if row is None else dict(row)

    def read_audit_count(self):
        with closing(db.get_connection()) as connection:
            return connection.execute(
                """
                SELECT COUNT(*)
                FROM signature_audit_log
                """
            ).fetchone()[0]

    def set_lockout_state(
        self,
        count,
        locked_until=None,
    ):
        self.execute(
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
                self.USER_ID,
            ),
        )

    def assert_lockout_state(
        self,
        count,
        locked_until=None,
    ):
        row = self.read_signing_row()

        self.assertIsNotNone(row)

        self.assertEqual(
            row["failed_unlock_count"],
            count,
        )

        self.assertEqual(
            row["locked_until"],
            locked_until,
        )

    def update_material(self, field, value):
        # Only fixed, explicitly allowed test fixture columns
        # may be used to construct this SQL statement.
        allowed_fields = {
            "public_key_pem",
            "fingerprint",
            "certificate_der",
            "private_key_salt",
            "encrypted_private_key",
            "expires_at",
            "created_at",
        }

        self.assertIn(field, allowed_fields)

        self.execute(
            f"""
            UPDATE signing_keys
            SET {field} = ?
            WHERE user_id = ?
            """,
            (value, self.USER_ID),
        )

    def replace_encrypted_private_key(
        self,
        private_der,
        *,
        context=None,
    ):
        """Encrypt deliberately substituted material with a real KEK."""

        row = self.read_signing_row()

        kek = _derive_signing_kek(
            self.PASSWORD,
            row["private_key_salt"],
        )

        if context is None:
            context = self.signing_context

        envelope = encrypt_blob(
            private_der,
            kek,
            "AES",
            context,
        )

        del kek

        self.update_material(
            "encrypted_private_key",
            envelope,
        )

    def assert_recovery_failure(self):
        before = self.read_signing_row()

        with self.assertRaises(KeyUnlockError):
            unlock_signing_key(
                self.USER_ID,
                self.PASSWORD,
            )

        after = self.read_signing_row()

        expected = dict(before)
        expected["failed_unlock_count"] += 1

        # Only the failed-attempt counter may change.
        self.assertEqual(
            after,
            expected,
        )

    # ========================================================
    # Successful recovery and actual signing operations
    # ========================================================

    def test_successful_signing_key_unlock(self):
        before = self.read_signing_row()

        key = unlock_signing_key(
            self.USER_ID,
            self.PASSWORD,
        )

        self.assertIsInstance(
            key,
            RSA.RsaKey,
        )

        self.assertTrue(
            key.has_private()
        )

        self.assertEqual(
            key.size_in_bits(),
            3072,
        )

        self.assertEqual(
            (
                key.n,
                key.e,
                key.d,
            ),
            (
                self.original_private.n,
                self.original_private.e,
                self.original_private.d,
            ),
        )

        self.assertEqual(
            key.public_key().export_key(
                format="DER"
            ),
            self.original_private.public_key().export_key(
                format="DER"
            ),
        )

        message = b"Recovered signing key integration test"

        signature = rsa_sign(
            key,
            message,
        )

        self.assertTrue(
            rsa_verify(
                before["public_key_pem"],
                message,
                signature,
            )
        )

        pkcs1_15.new(
            key.public_key()
        ).verify(
            SHA256.new(message),
            signature,
        )

        self.assertEqual(
            self.read_signing_row(),
            before,
        )

        self.assertEqual(
            self.read_audit_count(),
            0,
        )

    def test_recovered_key_builds_valid_cms(self):
        from cms import (
            build_cms_signed_data,
            parse_cms_signed_data,
        )

        key = unlock_signing_key(
            self.USER_ID,
            self.PASSWORD,
        )

        document = (
            b"Medimo signing key unlock CMS test.\x00\xff"
        )

        digest = SHA256.new(
            document
        ).digest()

        row = get_signing_key(
            self.USER_ID
        )

        cms_der = build_cms_signed_data(
            digest,
            row["certificate_der"],
            key,
            self.NOW,
        )

        parsed = parse_cms_signed_data(
            cms_der
        )

        self.assertEqual(
            parsed["certificate_der"],
            row["certificate_der"],
        )

        self.assertEqual(
            parsed["message_digest"],
            digest,
        )

        self.assertEqual(
            parsed["signing_time"],
            self.NOW,
        )

        self.assertTrue(
            rsa_verify(
                row["public_key_pem"],
                parsed["signed_attrs_der"],
                parsed["signature"],
            )
        )

        self.assertLessEqual(
            len(cms_der),
            8192,
        )

    # ========================================================
    # Input validation and failed recovery
    # ========================================================

    def test_wrong_password_increments_counter(self):
        before = self.read_signing_row()

        with self.assertRaises(KeyUnlockError):
            unlock_signing_key(
                self.USER_ID,
                self.WRONG_PASSWORD,
            )

        expected = dict(before)
        expected["failed_unlock_count"] = 1

        self.assertEqual(
            self.read_signing_row(),
            expected,
        )

    def test_invalid_user_ids_are_rejected(self):
        values = (
            None,
            True,
            False,
            0,
            -1,
            "7",
            b"7",
            7.0,
            1 << 63,
            10**100,
        )

        before = self.read_signing_row()

        with patch(
            "signing_keys.get_connection",
            side_effect=AssertionError(
                "Invalid user ID reached the database"
            ),
        ) as factory:

            for value in values:
                with self.subTest(user_id=value):
                    with self.assertRaises(ValueError):
                        unlock_signing_key(
                            value,
                            self.PASSWORD,
                        )

            factory.assert_not_called()

        self.assertEqual(
            self.read_signing_row(),
            before,
        )

    def test_invalid_password_inputs_are_rejected(self):
        values = (
            None,
            "",
            123,
            True,
            b"password",
            "\ud800",
        )

        with patch(
            "signing_keys._derive_signing_kek",
            side_effect=AssertionError(
                "Invalid password reached the KDF"
            ),
        ) as derive:

            for value in values:
                with self.subTest(
                    input_type=type(value).__name__
                ):
                    self.set_lockout_state(0)

                    with self.assertRaises(KeyUnlockError):
                        unlock_signing_key(
                            self.USER_ID,
                            value,
                        )

                    self.assert_lockout_state(1)

            derive.assert_not_called()

    def test_missing_signing_key_is_rejected(self):
        before = self.read_signing_row()

        with patch(
            "signing_keys._derive_signing_kek",
            side_effect=AssertionError(
                "Missing key reached KDF"
            ),
        ) as derive:

            for user_id in (
                self.EMPTY_USER_ID,
                999999,
            ):
                with self.subTest(user_id=user_id):
                    with self.assertRaises(KeyUnlockError):
                        unlock_signing_key(
                            user_id,
                            self.PASSWORD,
                        )

            derive.assert_not_called()

        self.assertEqual(
            self.read_signing_row(),
            before,
        )

    # ========================================================
    # Lockout boundaries
    # ========================================================

    def test_complete_five_failure_sequence(self):
        for attempt in range(1, 6):
            expected_error = (
                KeyUnlockError
                if attempt < 5
                else KeyLockedError
            )

            with self.subTest(attempt=attempt):
                with self.assertRaises(expected_error):
                    unlock_signing_key(
                        self.USER_ID,
                        self.WRONG_PASSWORD,
                    )

                if attempt < 5:
                    self.assert_lockout_state(
                        attempt,
                    )

                else:
                    expected_until = (
                        self.NOW
                        + timedelta(minutes=15)
                    )

                    self.assert_lockout_state(
                        5,
                        expected_until.isoformat(),
                    )

                    actual_until = datetime.fromisoformat(
                        self.read_signing_row()[
                            "locked_until"
                        ]
                    )

                    self.assertEqual(
                        actual_until - self.NOW,
                        timedelta(minutes=15),
                    )

                    self.assertEqual(
                        actual_until.utcoffset(),
                        timedelta(0),
                    )

    def test_active_lockout_rejects_without_extension(self):
        locked_until = (
            self.NOW
            + timedelta(minutes=15)
        ).isoformat()

        self.set_lockout_state(
            5,
            locked_until,
        )

        before = self.read_signing_row()

        with patch(
            "signing_keys._derive_signing_kek",
            side_effect=AssertionError(
                "Active lockout must not run scrypt"
            ),
        ) as derive:

            for elapsed in (
                0,
                60,
                899,
            ):
                self.clock.return_value = (
                    self.NOW
                    + timedelta(seconds=elapsed)
                )

                for password in (
                    self.PASSWORD,
                    self.WRONG_PASSWORD,
                ):
                    with self.subTest(
                        elapsed=elapsed,
                        correct=password == self.PASSWORD,
                    ):
                        with self.assertRaises(KeyLockedError):
                            unlock_signing_key(
                                self.USER_ID,
                                password,
                            )

                        self.assertEqual(
                            self.read_signing_row(),
                            before,
                        )

            derive.assert_not_called()

    def test_expired_lockout_wrong_password_restarts_counter(self):
        self.set_lockout_state(
            5,
            self.NOW.isoformat(),
        )

        # now == locked_until is no longer an active lockout.
        with self.assertRaises(KeyUnlockError):
            unlock_signing_key(
                self.USER_ID,
                self.WRONG_PASSWORD,
            )

        self.assert_lockout_state(
            1,
            None,
        )

    def test_expired_lockout_correct_password_resets_state(self):
        self.set_lockout_state(
            5,
            self.NOW.isoformat(),
        )

        key = unlock_signing_key(
            self.USER_ID,
            self.PASSWORD,
        )

        self.assertTrue(
            key.has_private()
        )

        self.assertEqual(
            key.n,
            self.original_private.n,
        )

        self.assert_lockout_state(
            0,
            None,
        )

    def test_success_resets_partial_failed_counter(self):
        self.set_lockout_state(4)

        before = self.read_signing_row()

        key = unlock_signing_key(
            self.USER_ID,
            self.PASSWORD,
        )

        self.assertEqual(
            key.n,
            self.original_private.n,
        )

        expected = dict(before)

        expected["failed_unlock_count"] = 0
        expected["locked_until"] = None

        self.assertEqual(
            self.read_signing_row(),
            expected,
        )

    # ========================================================
    # Concurrent requests
    # ========================================================

    def test_concurrent_failed_attempts_remain_capped_at_five(self):
        self.set_lockout_state(4)

        barrier = Barrier(2)

        original_recover = (
            signing_keys._recover_signing_private_key
        )

        def synchronized_recovery(
            user_id,
            password,
            row,
        ):
            # Both requests perform real scrypt/decryption.
            # Synchronize only before their final transaction.
            try:
                return original_recover(
                    user_id,
                    password,
                    row,
                )

            except KeyUnlockError:
                barrier.wait(timeout=30)
                raise

        def attempt():
            try:
                unlock_signing_key(
                    self.USER_ID,
                    self.WRONG_PASSWORD,
                )

            except (
                KeyUnlockError,
                KeyLockedError,
            ) as exc:
                return type(exc)

            raise AssertionError(
                "Wrong password unexpectedly unlocked key"
            )

        with patch(
            "signing_keys._recover_signing_private_key",
            side_effect=synchronized_recovery,
        ):
            with ThreadPoolExecutor(
                max_workers=2
            ) as executor:

                futures = [
                    executor.submit(attempt)
                    for _ in range(2)
                ]

                results = [
                    future.result(timeout=60)
                    for future in futures
                ]

        self.assertEqual(
            results,
            [
                KeyLockedError,
                KeyLockedError,
            ],
        )

        self.assert_lockout_state(
            5,
            (
                self.NOW
                + timedelta(minutes=15)
            ).isoformat(),
        )

    def test_concurrent_lockout_blocks_successful_recovery(self):
        self.set_lockout_state(4)

        original_recover = (
            signing_keys._recover_signing_private_key
        )

        def recover_then_concurrent_failure(
            user_id,
            password,
            row,
        ):
            key = original_recover(
                user_id,
                password,
                row,
            )

            if password == self.PASSWORD:
                # Another genuine failed unlock creates an
                # active lockout before this request finalizes.
                with self.assertRaises(KeyLockedError):
                    unlock_signing_key(
                        user_id,
                        self.WRONG_PASSWORD,
                    )

            return key

        with patch(
            "signing_keys._recover_signing_private_key",
            side_effect=recover_then_concurrent_failure,
        ):
            with self.assertRaises(KeyLockedError):
                unlock_signing_key(
                    self.USER_ID,
                    self.PASSWORD,
                )

        self.assert_lockout_state(
            5,
            (
                self.NOW
                + timedelta(minutes=15)
            ).isoformat(),
        )

    # ========================================================
    # Authenticated encryption and malformed recovered keys
    # ========================================================

    def test_corrupted_encrypted_private_key_is_rejected(self):
        envelope = self.signing_row[
            "encrypted_private_key"
        ]

        modified = (
            envelope[:-1]
            + bytes([envelope[-1] ^ 1])
        )

        self.update_material(
            "encrypted_private_key",
            modified,
        )

        self.assert_recovery_failure()

    def test_corrupted_salt_is_rejected(self):
        original = self.signing_row[
            "private_key_salt"
        ]

        altered = (
            bytes([original[0] ^ 1])
            + original[1:]
        )

        for salt in (
            b"",
            bytes(15),
            bytes(17),
            "not-bytes-value!",
            altered,
        ):
            with self.subTest(
                salt_type=type(salt).__name__,
                length=len(salt),
            ):
                self.set_lockout_state(0)

                self.update_material(
                    "private_key_salt",
                    salt,
                )

                self.assert_recovery_failure()

    def test_wrong_authenticated_context_is_rejected(self):
        private_der = (
            self.original_private.export_key(
                format="DER",
                pkcs=8,
            )
        )

        contexts = (
            self.encryption_context,
            {
                "owner_id": self.USER_ID + 1,
                "kind": "signing_key",
                "item_id": "signing_key",
            },
        )

        for context in contexts:
            with self.subTest(context=context):
                self.set_lockout_state(0)

                self.replace_encrypted_private_key(
                    private_der,
                    context=context,
                )

                self.assert_recovery_failure()

    def test_recovered_rsa2048_private_key_is_rejected(self):
        other_key = RSA.generate(2048)

        self.replace_encrypted_private_key(
            other_key.export_key(
                format="DER",
                pkcs=8,
            )
        )

        self.assert_recovery_failure()

    def test_recovered_public_only_key_is_rejected(self):
        public_der = (
            self.original_private.public_key()
            .export_key(format="DER")
        )

        self.replace_encrypted_private_key(
            public_der,
        )

        self.assert_recovery_failure()

    def test_inconsistent_private_components_are_rejected(self):
        original = self.original_private

        inconsistent = RSA.construct(
            (
                original.n,
                original.e,
                original.d + 1,
                original.p,
                original.q,
            ),
            consistency_check=False,
        )

        self.replace_encrypted_private_key(
            inconsistent.export_key(
                format="DER",
                pkcs=8,
            )
        )

        self.assert_recovery_failure()

    def test_explicit_private_component_validation_after_import(self):
        original = self.original_private

        inconsistent = RSA.construct(
            (
                original.n,
                original.e,
                original.d + 1,
                original.p,
                original.q,
            ),
            consistency_check=False,
        )

        original_import = RSA.import_key

        private_der = original.export_key(
            format="DER",
            pkcs=8,
        )

        def defensive_import_fixture(
            encoded,
            *args,
            **kwargs,
        ):
            # Defensive boundary injection only.
            # The real KEK and decryption still execute.
            if encoded == private_der:
                return inconsistent

            return original_import(
                encoded,
                *args,
                **kwargs,
            )

        with patch(
            "signing_keys.RSA.import_key",
            side_effect=defensive_import_fixture,
        ) as imported:

            self.assert_recovery_failure()

            imported.assert_called_with(
                private_der,
            )

    def test_invalid_pkcs8_encoding_is_rejected(self):
        invalid_values = (
            b"not a private key",
            b"\x30\x00",
            self.original_private.export_key(
                format="DER",
                pkcs=1,
            ),
        )

        for private_der in invalid_values:
            with self.subTest(
                length=len(private_der)
            ):
                self.set_lockout_state(0)

                self.replace_encrypted_private_key(
                    private_der,
                )

                self.assert_recovery_failure()

    # ========================================================
    # Stored public key and certificate consistency
    # ========================================================

    def test_stored_public_key_mismatch_is_rejected(self):
        self.update_material(
            "public_key_pem",
            self.encryption_row[
                "public_key_pem"
            ],
        )

        self.assert_recovery_failure()

    def test_stored_fingerprint_mismatch_is_rejected(self):
        self.update_material(
            "fingerprint",
            self.encryption_row[
                "fingerprint"
            ],
        )

        self.assert_recovery_failure()

    def test_stored_certificate_public_key_mismatch_is_rejected(self):
        original = parse_certificate(
            self.signing_row[
                "certificate_der"
            ]
        )

        other_certificate = build_self_signed_certificate(
            self.encryption_private,
            self.USERNAME,
            original["not_before"],
            original["not_after"],
        )

        parsed = parse_certificate(
            other_certificate
        )

        self.assertTrue(
            rsa_verify(
                parsed["public_key_pem"],
                parsed["tbs_der"],
                parsed["signature"],
            )
        )

        self.update_material(
            "certificate_der",
            other_certificate,
        )

        self.assert_recovery_failure()

    def test_stored_certificate_signature_tampering_is_rejected(self):
        certificate = self.signing_row[
            "certificate_der"
        ]

        modified = (
            certificate[:-1]
            + bytes([certificate[-1] ^ 1])
        )

        parsed = parse_certificate(
            modified
        )

        self.assertFalse(
            rsa_verify(
                parsed["public_key_pem"],
                parsed["tbs_der"],
                parsed["signature"],
            )
        )

        self.update_material(
            "certificate_der",
            modified,
        )

        self.assert_recovery_failure()

    def test_malformed_stored_certificate_is_rejected(self):
        original = self.signing_row[
            "certificate_der"
        ]

        for certificate in (
            b"",
            b"\x30\x00",
            original[:-1],
            original + b"\x00",
        ):
            with self.subTest(
                length=len(certificate)
            ):
                self.set_lockout_state(0)

                self.update_material(
                    "certificate_der",
                    certificate,
                )

                self.assert_recovery_failure()

    def test_stored_certificate_expiry_mismatch_is_rejected(self):
        expiry = datetime.fromisoformat(
            self.signing_row["expires_at"]
        )

        values = (
            (
                expiry
                + timedelta(seconds=1)
            ).isoformat(),
            "not-a-timestamp",
            expiry.replace(tzinfo=None).isoformat(),
        )

        for value in values:
            with self.subTest(expires_at=value):
                self.set_lockout_state(0)

                self.update_material(
                    "expires_at",
                    value,
                )

                self.assert_recovery_failure()

    def test_stored_certificate_created_at_mismatch_is_rejected(self):
        original = datetime.fromisoformat(
            self.signing_row["created_at"]
        )

        modified = (
            original - timedelta(seconds=1)
        ).isoformat()

        self.update_material(
            "created_at",
            modified,
        )

        self.assert_recovery_failure()

    # ========================================================
    # Stale snapshots and concurrent material replacement
    # ========================================================

    def test_key_material_changes_during_unlock(self):
        original_recover = (
            signing_keys._recover_signing_private_key
        )

        cases = (
            (
                "public_key_pem",
                self.encryption_row[
                    "public_key_pem"
                ],
            ),
            (
                "fingerprint",
                self.encryption_row[
                    "fingerprint"
                ],
            ),
            (
                "certificate_der",
                b"\x30\x00",
            ),
            (
                "private_key_salt",
                self.encryption_row[
                    "private_key_salt"
                ],
            ),
            (
                "encrypted_private_key",
                self.encryption_row[
                    "encrypted_private_key"
                ],
            ),
            (
                "expires_at",
                "2040-01-01T00:00:00+00:00",
            ),
            (
                "created_at",
                "2020-01-01T00:00:00+00:00",
            ),
        )

        for field, replacement in cases:
            with self.subTest(field=field):
                self.assertNotEqual(
                    self.signing_row[field],
                    replacement,
                )

                self.set_lockout_state(2)

                def recover_then_replace(
                    user_id,
                    password,
                    row,
                ):
                    key = original_recover(
                        user_id,
                        password,
                        row,
                    )

                    # Separate SQLite connection simulates
                    # a concurrent key material replacement.
                    self.update_material(
                        field,
                        replacement,
                    )

                    return key

                try:
                    with patch(
                        "signing_keys._recover_signing_private_key",
                        side_effect=recover_then_replace,
                    ):
                        with self.assertRaises(KeyUnlockError):
                            unlock_signing_key(
                                self.USER_ID,
                                self.PASSWORD,
                            )

                    self.assertEqual(
                        self.read_signing_row()[field],
                        replacement,
                    )

                    # A stale recovery must not reset the
                    # security state of the replacement record.
                    self.assert_lockout_state(2)

                finally:
                    self.update_material(
                        field,
                        self.signing_row[field],
                    )

    def test_key_deleted_during_unlock(self):
        original_recover = (
            signing_keys._recover_signing_private_key
        )

        def recover_then_delete(
            user_id,
            password,
            row,
        ):
            key = original_recover(
                user_id,
                password,
                row,
            )

            self.execute(
                """
                DELETE FROM signing_keys
                WHERE user_id = ?
                """,
                (user_id,),
            )

            return key

        with patch(
            "signing_keys._recover_signing_private_key",
            side_effect=recover_then_delete,
        ):
            with self.assertRaises(KeyUnlockError):
                unlock_signing_key(
                    self.USER_ID,
                    self.PASSWORD,
                )

        self.assertIsNone(
            self.read_signing_row()
        )

    # ========================================================
    # Database transaction failure and connection cleanup
    # ========================================================

    def test_database_update_failure_rolls_back_and_returns_no_key(self):
        self.set_lockout_state(2)

        before = self.read_signing_row()

        # SQLite RAISE(FAIL) may preserve changes already made
        # by the statement until the transaction rolls back.
        self.execute(
            """
            CREATE TRIGGER test_fail_signing_unlock
            AFTER UPDATE ON signing_keys
            BEGIN
                SELECT RAISE(
                    FAIL,
                    'Injected signing unlock update failure'
                );
            END
            """
        )

        connections = []

        def track_connection():
            connection = db.get_connection()
            connections.append(connection)
            return connection

        with patch(
            "signing_keys.get_connection",
            side_effect=track_connection,
        ):
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "Injected signing unlock update failure",
            ):
                unlock_signing_key(
                    self.USER_ID,
                    self.PASSWORD,
                )

        self.assertEqual(
            self.read_signing_row(),
            before,
        )

        self.assertEqual(
            len(connections),
            2,
        )

        for connection in connections:
            with self.assertRaises(
                sqlite3.ProgrammingError
            ):
                connection.execute("SELECT 1")

        self.execute(
            """
            DROP TRIGGER test_fail_signing_unlock
            """
        )

        # The database remains usable after the rollback.
        key = unlock_signing_key(
            self.USER_ID,
            self.PASSWORD,
        )

        self.assertEqual(
            key.n,
            self.original_private.n,
        )

        self.assert_lockout_state(0)

    def test_database_commit_failure_returns_no_private_key(self):
        self.set_lockout_state(2)

        before = self.read_signing_row()

        # A deferred foreign-key violation causes the
        # final transaction COMMIT to fail, not its UPDATE.
        # This table exists exclusively in the test database.
        self.execute(
            """
            CREATE TABLE test_unlock_commit_guard (
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    DEFERRABLE INITIALLY DEFERRED
            )
            """
        )

        self.execute(
            """
            CREATE TRIGGER test_fail_signing_commit
            AFTER UPDATE ON signing_keys
            BEGIN
                INSERT INTO test_unlock_commit_guard (
                    user_id
                )
                VALUES (999999);
            END
            """
        )

        with self.assertRaises(sqlite3.IntegrityError):
            unlock_signing_key(
                self.USER_ID,
                self.PASSWORD,
            )

        self.assertEqual(
            self.read_signing_row(),
            before,
        )

        with closing(db.get_connection()) as connection:
            count = connection.execute(
                """
                SELECT COUNT(*)
                FROM test_unlock_commit_guard
                """
            ).fetchone()[0]

        self.assertEqual(count, 0)

    def test_connections_close_on_success_and_authentication_failure(self):
        for password in (
            self.PASSWORD,
            self.WRONG_PASSWORD,
        ):
            with self.subTest(
                correct=password == self.PASSWORD
            ):
                connections = []

                def track_connection():
                    connection = db.get_connection()
                    connections.append(connection)
                    return connection

                with patch(
                    "signing_keys.get_connection",
                    side_effect=track_connection,
                ):
                    if password == self.PASSWORD:
                        key = unlock_signing_key(
                            self.USER_ID,
                            password,
                        )

                        self.assertTrue(
                            key.has_private()
                        )

                    else:
                        with self.assertRaises(KeyUnlockError):
                            unlock_signing_key(
                                self.USER_ID,
                                password,
                            )

                self.assertEqual(
                    len(connections),
                    2,
                )

                for connection in connections:
                    with self.assertRaises(
                        sqlite3.ProgrammingError
                    ):
                        connection.execute(
                            "SELECT 1"
                        )

    def test_ignored_database_update_does_not_return_key(self):
        self.set_lockout_state(2)

        before = self.read_signing_row()

        self.execute(
            """
            CREATE TRIGGER test_ignore_signing_update
            BEFORE UPDATE ON signing_keys
            BEGIN
                SELECT RAISE(IGNORE);
            END
            """
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "security state was not updated",
        ):
            unlock_signing_key(
                self.USER_ID,
                self.PASSWORD,
            )

        self.assertEqual(
            self.read_signing_row(),
            before,
        )

    # ========================================================
    # Task 2 key and lockout isolation
    # ========================================================

    def test_task2_key_and_lockout_remain_unchanged(self):
        legacy_locked_until = (
            self.NOW
            + timedelta(minutes=15)
        ).isoformat()

        self.execute(
            """
            UPDATE user_keys
            SET
                failed_unlock_count = 5,
                locked_until = ?
            WHERE user_id = ?
            """,
            (
                legacy_locked_until,
                self.USER_ID,
            ),
        )

        before = self.read_encryption_row()

        key = unlock_signing_key(
            self.USER_ID,
            self.PASSWORD,
        )

        self.assertEqual(
            key.n,
            self.original_private.n,
        )

        self.assertNotEqual(
            key.n,
            self.encryption_private.n,
        )

        with self.assertRaises(KeyUnlockError):
            unlock_signing_key(
                self.USER_ID,
                self.WRONG_PASSWORD,
            )

        self.assert_lockout_state(1)

        self.assertEqual(
            self.read_encryption_row(),
            before,
        )

        self.assertEqual(
            self.read_audit_count(),
            0,
        )

    def test_signing_and_encryption_envelopes_cannot_be_swapped(self):
        before = self.read_encryption_row()

        # Even when the corresponding Task 2 salt is copied,
        # its envelope is authenticated to another context.
        self.update_material(
            "private_key_salt",
            before["private_key_salt"],
        )

        self.update_material(
            "encrypted_private_key",
            before["encrypted_private_key"],
        )

        self.assert_recovery_failure()

        # Test the opposite direction using the correct
        # signing KEK but the Task 2 authenticated context.
        signing_kek = _derive_signing_kek(
            self.PASSWORD,
            self.signing_row[
                "private_key_salt"
            ],
        )

        try:
            with self.assertRaises(InvalidEnvelopeError):
                decrypt_blob(
                    self.signing_row[
                        "encrypted_private_key"
                    ],
                    signing_kek,
                    "AES",
                    self.encryption_context,
                )

        finally:
            del signing_kek

        self.assertEqual(
            self.read_encryption_row(),
            before,
        )

    # ========================================================
    # Expiration policy and unexpected failures
    # ========================================================

    def test_expired_certificate_is_not_unlock_policy(self):
        expires_at = datetime.fromisoformat(
            self.signing_row["expires_at"]
        )

        self.clock.return_value = (
            expires_at
            + timedelta(seconds=1)
        )

        self.assertGreater(
            self.clock.return_value,
            expires_at,
        )

        key = unlock_signing_key(
            self.USER_ID,
            self.PASSWORD,
        )

        self.assertTrue(
            key.has_private()
        )

        self.assertEqual(
            key.n,
            self.original_private.n,
        )

        self.assert_lockout_state(0)

        # This does not authorize signing after expiry.
        # sign_pdf enforces expiration before unlock.

    def test_unexpected_internal_failure_is_not_counted(self):
        self.set_lockout_state(2)

        before = self.read_signing_row()

        with patch(
            "signing_keys._derive_signing_kek",
            side_effect=RuntimeError(
                "Injected internal KDF failure"
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "Injected internal KDF failure",
            ):
                unlock_signing_key(
                    self.USER_ID,
                    self.PASSWORD,
                )

        self.assertEqual(
            self.read_signing_row(),
            before,
        )

    def test_corrupted_lockout_metadata_fails_closed(self):
        cases = (
            (-1, None),
            (6, None),
            (5, None),
            (5, "not-a-timestamp"),
            (5, "2026-11-28T12:15:00"),
        )

        with patch(
            "signing_keys._derive_signing_kek",
            side_effect=AssertionError(
                "Corrupted lockout state reached KDF"
            ),
        ) as derive:

            for count, locked_until in cases:
                with self.subTest(
                    count=count,
                    locked_until=locked_until,
                ):
                    self.set_lockout_state(
                        count,
                        locked_until,
                    )

                    before = self.read_signing_row()

                    with self.assertRaises(KeyUnlockError):
                        unlock_signing_key(
                            self.USER_ID,
                            self.PASSWORD,
                        )

                    self.assertEqual(
                        self.read_signing_row(),
                        before,
                    )

            derive.assert_not_called()


if __name__ == "__main__":
    unittest.main()