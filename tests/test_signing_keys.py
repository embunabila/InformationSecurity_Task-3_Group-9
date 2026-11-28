import base64
import unittest
from unittest.mock import patch

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import pkcs1_15

from signing_keys import (
    _emsa_pkcs1_v1_5_encode,
    _emsa_pkcs1_v1_5_encode_digest,
    rsa_sign,
    rsa_verify,
)


# Published SHA-256 known-answer values; no production helpers used.
ABC_DIGEST = bytes.fromhex(
    "ba7816bf8f01cfea414140de5dae2223"
    "b00361a396177a9cb410ff61f20015ad"
)
EMPTY_DIGEST = bytes.fromhex(
    "e3b0c44298fc1c149afbf4c8996fb924"
    "27ae41e4649b934ca495991b7852b855"
)
NULL_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
ABSENT_PREFIX = bytes.fromhex("302f300b06096086480165030402010420")


class TestEMSAPKCS1v15(unittest.TestCase):
    def test_known_encoded_message(self):
        expected = bytes.fromhex(
            "0001 ffffffffffffffffffff 00"
            "3031300d060960864801650304020105000420"
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad"
        )
        self.assertEqual(len(expected), 64)
        self.assertEqual(_emsa_pkcs1_v1_5_encode(b"abc", 64), expected)
        self.assertEqual(
            _emsa_pkcs1_v1_5_encode_digest(ABC_DIGEST, 64), expected
        )

    def test_null_digestinfo_prefix(self):
        em = _emsa_pkcs1_v1_5_encode_digest(ABC_DIGEST, 256)
        self.assertEqual(em[-51:], NULL_PREFIX + ABC_DIGEST)

    def test_absent_digestinfo_prefix(self):
        em = _emsa_pkcs1_v1_5_encode_digest(
            ABC_DIGEST, 256, include_null=False
        )
        self.assertEqual(em[-49:], ABSENT_PREFIX + ABC_DIGEST)

    def test_modulus_lengths(self):
        # Independent padding lengths for 2048, 3072 and 4096 bits.
        for k, null_ps, absent_ps in ((256, 202, 204),
                                     (384, 330, 332),
                                     (512, 458, 460),
                                     (257, 203, 205)):
            for include_null, ps, prefix in (
                (True, null_ps, NULL_PREFIX),
                (False, absent_ps, ABSENT_PREFIX),
            ):
                with self.subTest(k=k, include_null=include_null):
                    expected = b"\x00\x01" + b"\xff" * ps + b"\x00" + prefix + ABC_DIGEST
                    em = _emsa_pkcs1_v1_5_encode_digest(
                        ABC_DIGEST, k, include_null=include_null
                    )
                    self.assertEqual(len(em), k)
                    self.assertEqual(em, expected)

    def test_minimum_padding_boundary(self):
        for k, include_null, prefix in ((62, True, NULL_PREFIX),
                                         (60, False, ABSENT_PREFIX)):
            with self.subTest(k=k):
                expected = bytes.fromhex("0001 ffffffffffffffff 00") + prefix + ABC_DIGEST
                self.assertEqual(
                    _emsa_pkcs1_v1_5_encode_digest(
                        ABC_DIGEST, k, include_null=include_null
                    ), expected
                )

    def test_insufficient_encoded_message_length(self):
        for k, include_null in ((61, True), (59, False), (1, True), (1, False)):
            with self.subTest(k=k, include_null=include_null):
                with self.assertRaises(ValueError):
                    _emsa_pkcs1_v1_5_encode_digest(
                        ABC_DIGEST, k, include_null=include_null
                    )

    def test_invalid_digest_types(self):
        for digest in (None, "x" * 32, 32, bytearray(32), memoryview(bytes(32)), True):
            with self.subTest(digest_type=type(digest).__name__):
                with self.assertRaises(ValueError):
                    _emsa_pkcs1_v1_5_encode_digest(digest, 256)

    def test_invalid_digest_lengths(self):
        for length in (0, 1, 31, 33, 64):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    _emsa_pkcs1_v1_5_encode_digest(bytes(length), 256)

    def test_invalid_message_types(self):
        for message in (None, "abc", 123, bytearray(b"abc"), memoryview(b"abc"), True):
            with self.subTest(message_type=type(message).__name__):
                with self.assertRaises(ValueError):
                    _emsa_pkcs1_v1_5_encode(message, 256)

    def test_invalid_em_lengths(self):
        for k in (0, -1, True, False, 256.0, "256", None, 513, 10**100):
            with self.subTest(k=k):
                with self.assertRaises(ValueError):
                    _emsa_pkcs1_v1_5_encode_digest(ABC_DIGEST, k)

    def test_invalid_include_null(self):
        for value in (None, 0, 1, "True", b"true"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    _emsa_pkcs1_v1_5_encode_digest(ABC_DIGEST, 256, include_null=value)

    def test_exact_padding_and_digest_placement(self):
        digest = bytes(range(32))
        for include_null, separator, prefix in ((True, 332, NULL_PREFIX),
                                                 (False, 334, ABSENT_PREFIX)):
            with self.subTest(include_null=include_null):
                em = _emsa_pkcs1_v1_5_encode_digest(digest, 384, include_null=include_null)
                self.assertEqual(len(em), 384)
                self.assertEqual(em[:2], b"\x00\x01")
                self.assertEqual(em[2:separator], b"\xff" * (separator - 2))
                self.assertEqual(em[separator:separator + 1], b"\x00")
                self.assertEqual(em[separator + 1:-32], prefix)
                self.assertEqual(em[-32:], digest)

    def test_empty_message(self):
        expected = b"\x00\x01" + b"\xff" * 202 + b"\x00" + NULL_PREFIX + EMPTY_DIGEST
        self.assertEqual(_emsa_pkcs1_v1_5_encode(b"", 256), expected)

    def test_message_with_absent_parameter(self):
        expected = b"\x00\x01" + b"\xff" * 204 + b"\x00" + ABSENT_PREFIX + ABC_DIGEST
        self.assertEqual(_emsa_pkcs1_v1_5_encode(b"abc", 256, include_null=False), expected)


class TestRSASign(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = RSA.generate(3072)
        cls.other_key = RSA.generate(3072)
        cls.message = b"Medimo RSA signing test"

    def reference_signature(self, message, key=None):
        if key is None:
            key = self.private_key
        return pkcs1_15.new(key).sign(SHA256.new(message))

    def test_successful_rsa3072_signing(self):
        signature = rsa_sign(self.private_key, self.message)
        self.assertIsInstance(signature, bytes)
        self.assertEqual(self.private_key.size_in_bits(), 3072)
        self.assertEqual(len(signature), self.private_key.size_in_bytes())

    def test_signature_length(self):
        self.assertEqual(len(rsa_sign(self.private_key, self.message)), 384)

    def test_signature_representative_range_and_recovered_em(self):
        signature = rsa_sign(self.private_key, b"abc")
        s = int.from_bytes(signature, "big")
        self.assertGreaterEqual(s, 0)
        self.assertLess(s, self.private_key.n)
        expected_em = (
            b"\x00\x01" + b"\xff" * 330 + b"\x00"
            + NULL_PREFIX + ABC_DIGEST
        )
        m = pow(s, self.private_key.e, self.private_key.n)
        self.assertEqual(m.to_bytes(384, "big"), expected_em)

    def test_deterministic_signature(self):
        first = rsa_sign(self.private_key, self.message)
        second = rsa_sign(self.private_key, self.message)
        self.assertEqual(first, second)

    def test_different_messages(self):
        self.assertNotEqual(
            rsa_sign(self.private_key, b"message A"),
            rsa_sign(self.private_key, b"message B"),
        )

    def test_different_private_keys(self):
        self.assertNotEqual(self.private_key.n, self.other_key.n)
        self.assertNotEqual(
            rsa_sign(self.private_key, self.message),
            rsa_sign(self.other_key, self.message),
        )

    def test_empty_message(self):
        signature = rsa_sign(self.private_key, b"")
        self.assertEqual(signature, self.reference_signature(b""))

    def test_invalid_message_types(self):
        for value in (None, "abc", 123, True, bytearray(b"abc"), memoryview(b"abc")):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(ValueError):
                    rsa_sign(self.private_key, value)

    def test_public_key_rejected(self):
        with self.assertRaises(ValueError):
            rsa_sign(self.private_key.public_key(), self.message)

    def test_invalid_key_inputs(self):
        for key in (None, 123, True, "private key", b"not a key", object()):
            with self.subTest(key_type=type(key).__name__):
                with self.assertRaises(ValueError):
                    rsa_sign(key, self.message)

    def test_wrong_key_sizes_rejected(self):
        for bits in (2048, 4096):
            with self.subTest(bits=bits):
                key = RSA.generate(bits)
                with self.assertRaises(ValueError):
                    rsa_sign(key, self.message)

    def test_reference_verification(self):
        signature = rsa_sign(self.private_key, self.message)
        # verify raises ValueError or TypeError for invalid signatures.
        pkcs1_15.new(self.private_key.public_key()).verify(
            SHA256.new(self.message), signature
        )

    def test_exact_reference_signature(self):
        for message in (b"abc", self.message, b"\x00\xff\x80", bytes(range(256))):
            with self.subTest(message=message):
                self.assertEqual(
                    rsa_sign(self.private_key, message),
                    self.reference_signature(message),
                )

    def test_leading_zero_signature_serialization(self):
        # Search using the independent signer, not the function under test.
        # A generated test key avoids committing any private key fixture.
        for counter in range(8192):
            message = b"leading-zero:" + counter.to_bytes(4, "big")
            expected = self.reference_signature(message)
            if expected[0] == 0:
                break
        else:
            self.fail("No leading-zero signature found within search limit")

        actual = rsa_sign(self.private_key, message)
        self.assertEqual(len(actual), 384)
        self.assertEqual(actual[:1], b"\x00")
        self.assertEqual(actual, expected)

    def test_inconsistent_rsa_private_key_rejected(self):
        key = self.private_key
        inconsistent = RSA.construct(
            (key.n, key.e, key.d + 1, key.p, key.q),
            consistency_check=False,
        )
        with self.assertRaises(ValueError):
            rsa_sign(inconsistent, self.message)

    def test_message_representative_out_of_range(self):
        k = self.private_key.size_in_bytes()
        for m in (self.private_key.n, self.private_key.n + 1):
            with self.subTest(m_equals_n=m == self.private_key.n):
                with patch(
                    "signing_keys._emsa_pkcs1_v1_5_encode",
                    return_value=m.to_bytes(k, "big"),
                ):
                    with self.assertRaisesRegex(ValueError, "representative out of range"):
                        rsa_sign(self.private_key, self.message)


class TestRSAVerify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A genuine e=3 key exercises the classic padding-validation risk.
        # Other keys exercise both boundary sizes and a non-byte-aligned size.
        cls.keys = {bits: RSA.generate(bits, e=3 if bits == 2048 else 65537)
                    for bits in (2048, 2049, 3072, 4096)}
        cls.key = cls.keys[2048]
        cls.pem = cls.key.public_key().export_key()
        cls.k = cls.key.size_in_bytes()
        cls.message = b"abc"
        cls.signature = pkcs1_15.new(cls.key).sign(SHA256.new(cls.message))

    @staticmethod
    def reference_signature(key, message):
        return pkcs1_15.new(key).sign(SHA256.new(message))

    def raw_sign_em(self, em):
        """Test-only private operation: recover exactly the supplied EM."""
        self.assertEqual(len(em), self.k)
        m = int.from_bytes(em, "big")
        self.assertLess(m, self.key.n)
        s = pow(m, self.key.d, self.key.n)
        signature = s.to_bytes(self.k, "big")
        self.assertEqual(pow(s, self.key.e, self.key.n).to_bytes(self.k, "big"), em)
        return signature

    def independent_em(self, prefix=NULL_PREFIX):
        # Known SHA-256(abc) and independently specified DigestInfo bytes.
        t = prefix + ABC_DIGEST
        return b"\x00\x01" + b"\xff" * (self.k - len(t) - 3) + b"\x00" + t

    def assert_bad_em(self, em):
        signature = self.raw_sign_em(em)
        self.assertIs(rsa_verify(self.pem, self.message, signature), False)

    @staticmethod
    def public_pem(n, e):
        # Independently construct a PKCS#1 public-key PEM, including invalid
        # components that RSA.construct would normally refuse to serialize.
        def tlv(tag, content):
            length = len(content)
            if length < 128:
                size = bytes([length])
            else:
                value = length.to_bytes((length.bit_length() + 7) // 8, "big")
                size = bytes([0x80 | len(value)]) + value
            return bytes([tag]) + size + content

        def integer(value):
            bits = value.bit_length() if value >= 0 else (~value).bit_length()
            return tlv(2, value.to_bytes(max(1, (bits + 8) // 8), "big", signed=True))

        der = tlv(0x30, integer(n) + integer(e))
        return (b"-----BEGIN RSA PUBLIC KEY-----\n" + base64.encodebytes(der)
                + b"-----END RSA PUBLIC KEY-----\n")

    def test_successful_verification_of_rsa_sign(self):
        key = self.keys[3072]
        self.assertIs(rsa_verify(key.public_key().export_key(), self.message,
                                 rsa_sign(key, self.message)), True)

    def test_reference_interoperability(self):
        for message in (b"abc", b"\x00\xff\x80", bytes(range(256))):
            with self.subTest(message=message):
                self.assertIs(rsa_verify(self.pem, message,
                                         self.reference_signature(self.key, message)), True)

    def test_supported_modulus_sizes(self):
        for bits, key in self.keys.items():
            with self.subTest(bits=bits):
                self.assertEqual(key.n.bit_length(), bits)
                signature = self.reference_signature(key, self.message)
                self.assertEqual(len(signature), (bits + 7) // 8)
                self.assertIs(rsa_verify(key.public_key().export_key(), self.message, signature), True)

    def test_valid_digestinfo_null(self):
        self.assertIs(rsa_verify(self.pem, self.message,
                                 self.raw_sign_em(self.independent_em(NULL_PREFIX))), True)

    def test_valid_digestinfo_absent(self):
        self.assertIs(rsa_verify(self.pem, self.message,
                                 self.raw_sign_em(self.independent_em(ABSENT_PREFIX))), True)

    def test_empty_message_verification(self):
        self.assertIs(rsa_verify(self.pem, b"", self.reference_signature(self.key, b"")), True)

    def test_modified_message(self):
        self.assertIs(rsa_verify(self.pem, b"abd", self.signature), False)

    def test_signature_one_bit_modified(self):
        tampered = self.signature[:-1] + bytes([self.signature[-1] ^ 1])
        self.assertIs(rsa_verify(self.pem, self.message, tampered), False)

    def test_signature_from_other_key(self):
        # Same modulus length, so rejection cannot be explained by length.
        other = RSA.generate(2048)
        self.assertIs(rsa_verify(other.public_key().export_key(), self.message, self.signature), False)

    def test_wrong_signature_lengths(self):
        for signature in (b"", self.signature[1:], b"\x00" + self.signature, self.signature + b"\x00"):
            with self.subTest(length=len(signature)):
                self.assertIs(rsa_verify(self.pem, self.message, signature), False)

    def test_signature_representative_out_of_range(self):
        for s in (self.key.n, self.key.n + 1, (1 << (8 * self.k)) - 1):
            with self.subTest(representative=s):
                self.assertIs(rsa_verify(self.pem, self.message, s.to_bytes(self.k, "big")), False)

    def test_zero_signature_rejected(self):
        self.assertIs(rsa_verify(self.pem, self.message, bytes(self.k)), False)

    def test_malformed_public_key_pem(self):
        for pem in (b"", b"not a PEM", b"-----BEGIN PUBLIC KEY-----\n!\n-----END PUBLIC KEY-----",
                    self.pem[:40], "-----BEGIN PUBLIC KEY-----\n\u2603"):
            with self.subTest(pem=pem):
                self.assertIs(rsa_verify(pem, self.message, self.signature), False)

    def test_non_rsa_public_key(self):
        pem = ECC.generate(curve="P-256").public_key().export_key(format="PEM")
        self.assertIs(rsa_verify(pem, self.message, self.signature), False)

    def test_private_key_and_non_pem_rejected(self):
        for pem in (self.key.export_key(), self.key.public_key().export_key(format="DER")):
            with self.subTest(pem_format=pem[:20]):
                self.assertIs(rsa_verify(pem, self.message, self.signature), False)

    def test_pem_text_and_pkcs1_public_key(self):
        for pem in (self.pem.decode("ascii"), self.public_pem(self.key.n, self.key.e)):
            with self.subTest(pem_type=type(pem).__name__):
                self.assertIs(rsa_verify(pem, self.message, self.signature), True)

    def test_unsupported_key_sizes(self):
        for bits in (2047, 4097):
            with self.subTest(bits=bits):
                # Real RSA keys just outside each boundary.
                key = RSA.generate(bits)
                self.assertEqual(key.n.bit_length(), bits)
                signature = self.reference_signature(key, self.message)
                self.assertEqual(len(signature), (bits + 7) // 8)
                self.assertIs(rsa_verify(key.public_key().export_key(), self.message, signature), False)

    def test_invalid_public_exponents(self):
        for e in (0, 1, 2, 4, -3, self.key.n, self.key.n + 2):
            with self.subTest(exponent=e):
                pem = self.public_pem(self.key.n, e)
                self.assertIs(rsa_verify(pem, self.message, self.signature), False)

    def test_invalid_public_modulus(self):
        for n in (0, -self.key.n, self.key.n - 1):
            with self.subTest(modulus=n):
                self.assertIs(rsa_verify(self.public_pem(n, 65537), self.message, self.signature), False)

    def test_inconsistent_public_components(self):
        # An odd, in-range n that shares a factor with e is invalid.
        n = 3 * ((1 << 2046) + 1)
        self.assertEqual(n.bit_length(), 2048)
        self.assertIs(rsa_verify(self.public_pem(n, 3), self.message, self.signature), False)

    def test_invalid_input_types(self):
        for value in (None, 1, True, bytearray(b"abc"), memoryview(b"abc"), object()):
            with self.subTest(value_type=type(value).__name__):
                self.assertIs(rsa_verify(value, self.message, self.signature), False)
                self.assertIs(rsa_verify(self.pem, value, self.signature), False)
                self.assertIs(rsa_verify(self.pem, self.message, value), False)
        self.assertIs(rsa_verify(self.pem, "abc", self.signature), False)
        self.assertIs(rsa_verify(self.pem, self.message, "signature"), False)

    def test_valid_leading_zero_signature(self):
        # Search independent signatures, then check full-length serialization.
        for counter in range(8192):
            message = b"verify-leading-zero:" + counter.to_bytes(4, "big")
            signature = self.reference_signature(self.key, message)
            if signature[0] == 0:
                break
        else:
            self.fail("No leading-zero signature found within search limit")
        self.assertEqual(len(signature), self.k)
        self.assertIs(rsa_verify(self.pem, message, signature), True)
        self.assertIs(rsa_verify(self.pem, message, signature[1:]), False)

    def test_malformed_em_incorrect_header(self):
        em = self.independent_em()
        for header in (b"\x00\x00", b"\x00\x02", b"\x01\x01"):
            with self.subTest(header=header):
                self.assert_bad_em(header + em[2:])

    def test_malformed_em_insufficient_ff_padding(self):
        t = NULL_PREFIX + ABC_DIGEST
        # Seven FF bytes, separator, extra filler, then the correct DigestInfo.
        em = b"\x00\x01" + b"\xff" * 7 + b"\x00" + b"\xaa" * (self.k - 10 - len(t)) + t
        self.assert_bad_em(em)

    def test_malformed_em_incorrect_separator(self):
        em = self.independent_em()
        separator = self.k - 52
        self.assertEqual(em[separator], 0)
        self.assert_bad_em(em[:separator] + b"\x01" + em[separator + 1:])

    def test_malformed_em_incorrect_digestinfo(self):
        em = self.independent_em()
        # Change SHA-256 OID's final arc from 1 to 2 (same byte length).
        wrong_prefix = bytes.fromhex("3031300d060960864801650304020205000420")
        self.assert_bad_em(em[:-51] + wrong_prefix + ABC_DIGEST)

    def test_malformed_em_incorrect_digest(self):
        em = self.independent_em()
        self.assert_bad_em(em[:-1] + bytes([em[-1] ^ 1]))

    def test_malformed_em_trailing_garbage(self):
        # Valid-looking DigestInfo followed by unexpected bytes, total k bytes.
        t = NULL_PREFIX + ABC_DIGEST
        for garbage in (b"\x00", b"\x01\x02\x03", b"\xaa" * 32):
            with self.subTest(garbage=garbage):
                em = (b"\x00\x01" + b"\xff" * (self.k - len(t) - len(garbage) - 3)
                      + b"\x00" + t + garbage)
                self.assert_bad_em(em)

    def test_malformed_em_correct_digest_wrong_padding(self):
        em = self.independent_em()
        for index, value in ((2, 0x00), (10, 0x7f), (100, 0xfe)):
            with self.subTest(index=index, value=value):
                self.assert_bad_em(em[:index] + bytes([value]) + em[index + 1:])

    def test_hash_once_and_both_full_comparisons(self):
        # Spy on real operations, including the case where NULL matches first.
        from signing_keys import hmac
        for prefix in (NULL_PREFIX, ABSENT_PREFIX):
            em = self.independent_em(prefix)
            signature = self.raw_sign_em(em)
            with self.subTest(prefix=prefix):
                with patch("signing_keys.SHA256.new", wraps=SHA256.new) as hash_spy:
                    with patch("signing_keys.hmac.compare_digest", wraps=hmac.compare_digest) as compare_spy:
                        self.assertIs(rsa_verify(self.pem, self.message, signature), True)
                hash_spy.assert_called_once_with(self.message)
                self.assertEqual(compare_spy.call_count, 2)
                self.assertEqual(compare_spy.call_args_list[0].args,
                                 (em, self.independent_em(NULL_PREFIX)))
                self.assertEqual(compare_spy.call_args_list[1].args,
                                 (em, self.independent_em(ABSENT_PREFIX)))


if __name__ == "__main__":
    unittest.main()
