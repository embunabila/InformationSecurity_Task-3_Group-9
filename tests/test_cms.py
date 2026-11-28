import shutil
import subprocess
import tempfile
import unittest

from datetime import datetime, timedelta, timezone
from pathlib import Path

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from certificate import (
    build_self_signed_certificate,
    parse_certificate,
)

from cms import (
    build_cms_signed_data,
    parse_cms_signed_data,
)

from der import (
    DerError,
    MAX_INPUT_SIZE,
    MAX_ELEMENT_LENGTH,
    MAX_DEPTH,
    MAX_CHILDREN,
    MAX_TOTAL_ELEMENTS,
    decode_children,
    decode_explicit,
    decode_implicit,
    decode_value,
    parse_der,
)

from share_errors import (
    InvalidSignatureError,
    UnsupportedSignatureError,
)

from signing_keys import rsa_verify


# ============================================================
# Independent DER constants
# ============================================================

ID_DATA = bytes.fromhex(
    "06092a864886f70d010701"
)

ID_SIGNED_DATA = bytes.fromhex(
    "06092a864886f70d010702"
)

SHA256_ABSENT = bytes.fromhex(
    "300b0609608648016503040201"
)

SHA256_NULL = bytes.fromhex(
    "300d06096086480165030402010500"
)

SHA384_ABSENT = bytes.fromhex(
    "300b0609608648016503040202"
)

RSA_NULL = bytes.fromhex(
    "300d06092a864886f70d0101010500"
)

RSA_ABSENT = bytes.fromhex(
    "300b06092a864886f70d010101"
)

SHA256_RSA_NULL = bytes.fromhex(
    "300d06092a864886f70d01010b0500"
)

SHA256_RSA_ABSENT = bytes.fromhex(
    "300b06092a864886f70d01010b"
)

SHA384_RSA_NULL = bytes.fromhex(
    "300d06092a864886f70d01010c0500"
)

ATTR_CONTENT_TYPE = bytes.fromhex(
    "06092a864886f70d010903"
)

ATTR_MESSAGE_DIGEST = bytes.fromhex(
    "06092a864886f70d010904"
)

ATTR_SIGNING_TIME = bytes.fromhex(
    "06092a864886f70d010905"
)

UNKNOWN_ATTR = bytes.fromhex(
    "06032a0304"
)

CN_OID = bytes.fromhex(
    "0603550403"
)

UNKNOWN_EXTENSION_OID = bytes.fromhex(
    "06032a0305"
)

INTEGER_ONE = bytes.fromhex("020101")
VERSION_3 = bytes.fromhex("a003020102")

PDF_PLACEHOLDER_SIZE = 8192


# ============================================================
# Independent fixture helpers
# ============================================================


def wire(tag, content):
    """Build a TLV without using production DER encoders."""

    size = len(content)

    if size < 128:
        length = bytes([size])

    else:
        count = (
            size.bit_length() + 7
        ) // 8

        length = (
            bytes([0x80 | count])
            + size.to_bytes(count, "big")
        )

    return bytes([tag]) + length + content


def nonminimal_wire(tag, content):
    """Deliberately encode an unnecessary leading zero in length."""

    size = len(content)

    length = size.to_bytes(
        max(1, (size.bit_length() + 7) // 8),
        "big",
    )

    length = b"\x00" + length

    return (
        bytes([tag, 0x80 | len(length)])
        + length
        + content
    )


def indefinite_wire(tag, content):
    """Construct a BER indefinite-length fixture."""

    return (
        bytes([tag, 0x80])
        + content
        + b"\x00\x00"
    )


def integer(value):
    size = max(
        1,
        (value.bit_length() + 8) // 8,
    )

    return wire(
        0x02,
        value.to_bytes(
            size,
            "big",
            signed=True,
        ),
    )


def sequence(*elements):
    return wire(
        0x30,
        b"".join(elements),
    )


def set_of(*elements):
    return wire(
        0x31,
        b"".join(sorted(elements)),
    )


def attribute(oid, *values):
    return sequence(
        oid,
        set_of(*values),
    )


def name(common_name):
    return sequence(
        set_of(
            sequence(
                CN_OID,
                wire(
                    0x0c,
                    common_name.encode("utf-8"),
                ),
            ),
        ),
    )


def make_external_certificate(
    subject_key,
    issuer_key,
    *,
    serial=128,
    self_issued=False,
    extension_size=0,
):
    """Independently build a certificate signed using the reference RSA."""

    subject = name("External Signer")

    issuer = (
        subject
        if self_issued
        else name("External Test CA")
    )

    validity = sequence(
        wire(0x17, b"260101000000Z"),
        wire(0x18, b"20520101000000Z"),
    )

    spki = subject_key.public_key().export_key(
        format="DER"
    )

    extensions = b""

    if extension_size:
        extension = sequence(
            UNKNOWN_EXTENSION_OID,
            wire(
                0x04,
                wire(
                    0x04,
                    b"x" * extension_size,
                ),
            ),
        )

        extensions = wire(
            0xa3,
            sequence(extension),
        )

    tbs_der = sequence(
        VERSION_3,
        integer(serial),
        SHA256_RSA_NULL,
        issuer,
        validity,
        subject,
        spki,
        extensions,
    )

    signature = pkcs1_15.new(
        issuer_key
    ).sign(
        SHA256.new(tbs_der)
    )

    return sequence(
        tbs_der,
        SHA256_RSA_NULL,
        wire(
            0x03,
            b"\x00" + signature,
        ),
    )


# ============================================================
# Shared CMS fixtures and assertions
# ============================================================


class TestCMS(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.keys = {
            bits: RSA.generate(bits)
            for bits in (2048, 3072, 4096)
        }

        cls.key = cls.keys[3072]

        cls.start = datetime(
            2026, 1, 1,
            tzinfo=timezone.utc,
        )

        cls.end = cls.start + timedelta(days=730)

        cls.signing_time = datetime(
            2026, 11, 28,
            12, 34, 56,
            tzinfo=timezone.utc,
        )

        cls.document = (
            b"Medimo detached CMS interoperability test.\n"
            b"Binary document bytes: \x00\x80\xff\r\n"
        )

        cls.digest = SHA256.new(
            cls.document
        ).digest()

        cls.certificate = build_self_signed_certificate(
            cls.key,
            "cms_test_user",
            cls.start,
            cls.end,
        )

        cls.parsed_certificate = parse_certificate(
            cls.certificate
        )

        cls.cms = build_cms_signed_data(
            cls.digest,
            cls.certificate,
            cls.key,
            cls.signing_time,
        )

        cls.time_value = wire(
            0x17,
            b"261128123456Z",
        )

        cls.content_attribute = attribute(
            ATTR_CONTENT_TYPE,
            ID_DATA,
        )

        cls.digest_attribute = attribute(
            ATTR_MESSAGE_DIGEST,
            wire(0x04, cls.digest),
        )

        cls.time_attribute = attribute(
            ATTR_SIGNING_TIME,
            cls.time_value,
        )

        cls.default_attributes = (
            cls.content_attribute,
            cls.digest_attribute,
            cls.time_attribute,
        )

        # External certificate signatures are produced by a
        # different issuer key, not by the subject private key.
        cls.external_certificates = {
            bits: make_external_certificate(
                key,
                cls.keys[
                    4096 if bits == 2048 else 2048
                ],
            )
            for bits, key in cls.keys.items()
        }

    def parts(self, cms=None):
        """Decode known-good CMS for structural assertions."""

        cms = self.cms if cms is None else cms

        root = parse_der(cms)

        content_info = decode_value(
            root,
            0x30,
        )

        signed_data = decode_explicit(
            content_info[1],
            0,
        )

        fields = decode_value(
            signed_data,
            0x30,
        )

        signers = decode_value(
            fields[-1],
            0x31,
        )

        signer = decode_value(
            signers[0],
            0x30,
        )

        return {
            "root": root,
            "content_info": content_info,
            "signed_data": signed_data,
            "fields": fields,
            "signer_element": signers[0],
            "signer": signer,
        }

    def fixture(
        self,
        *,
        key=None,
        certificate=None,
        attributes=None,
        attrs_wire=None,
        include_attrs=True,
        digest_algorithm=SHA256_ABSENT,
        signer_digest_algorithm=None,
        signature_algorithm=RSA_NULL,
        sid=None,
        certificate_set=None,
        include_certificates=True,
        signer_set=None,
        encap=None,
        content_type=ID_SIGNED_DATA,
        sd_version=INTEGER_ONE,
        si_version=INTEGER_ONE,
        signature_override=None,
        signature_value=None,
        unsigned_attrs=b"",
        crls=b"",
    ):
        """Build CMS independently from production cms.py."""

        key = self.key if key is None else key

        certificate = (
            self.certificate
            if certificate is None
            else certificate
        )

        if sid is None:
            parsed_certificate = parse_certificate(
                certificate
            )

            sid = sequence(
                parsed_certificate["issuer_der"],
                integer(
                    parsed_certificate["serial"]
                ),
            )

        if attributes is None:
            attributes = self.default_attributes

        if attrs_wire is None:
            attrs_wire = wire(
                0xa0,
                b"".join(sorted(attributes)),
            )

        if include_attrs:
            signed_attrs_der = (
                b"\x31" + attrs_wire[1:]
            )

            signature_input = signed_attrs_der

        else:
            signed_attrs_der = None
            attrs_wire = b""
            signature_input = self.document

        signature = pkcs1_15.new(
            key
        ).sign(
            SHA256.new(signature_input)
        )

        if signature_override is not None:
            signature = signature_override

        if signature_value is None:
            signature_value = wire(
                0x04,
                signature,
            )

        if signer_digest_algorithm is None:
            signer_digest_algorithm = digest_algorithm

        signer_info = sequence(
            si_version,
            sid,
            signer_digest_algorithm,
            attrs_wire,
            signature_algorithm,
            signature_value,
            unsigned_attrs,
        )

        if signer_set is None:
            signer_set = set_of(signer_info)

        if certificate_set is None:
            certificate_set = wire(
                0xa0,
                certificate,
            )

        if not include_certificates:
            certificate_set = b""

        if encap is None:
            encap = sequence(ID_DATA)

        signed_data = sequence(
            sd_version,
            set_of(digest_algorithm),
            encap,
            certificate_set,
            crls,
            signer_set,
        )

        cms = sequence(
            content_type,
            wire(0xa0, signed_data),
        )

        return cms, signed_attrs_der, signature

    def assert_invalid(self, **kwargs):
        cms, _, _ = self.fixture(**kwargs)

        with self.assertRaises(
            InvalidSignatureError
        ):
            parse_cms_signed_data(cms)

    def assert_unsupported(self, **kwargs):
        cms, _, _ = self.fixture(**kwargs)

        with self.assertRaises(
            UnsupportedSignatureError
        ):
            parse_cms_signed_data(cms)

    def verify_parsed(self, parsed):
        certificate = parse_certificate(
            parsed["certificate_der"]
        )

        return rsa_verify(
            certificate["public_key_pem"],
            parsed["signed_attrs_der"],
            parsed["signature"],
        )

    def run_openssl(self, *args):
        return subprocess.run(
            ["openssl", *args],
            capture_output=True,
            timeout=30,
            check=False,
        )

    def assert_openssl_success(self, result):
        self.assertEqual(
            result.returncode,
            0,
            result.stderr.decode(errors="replace"),
        )

    # ========================================================
    # Builder tests
    # ========================================================

    def test_successful_generation_and_placeholder_capacity(self):
        self.assertIs(type(self.cms), bytes)
        self.assertGreater(len(self.cms), 0)

        self.assertLessEqual(
            len(self.cms),
            PDF_PLACEHOLDER_SIZE,
        )

        self.assertEqual(
            parse_der(self.cms).raw,
            self.cms,
        )

        padded = self.cms.ljust(
            PDF_PLACEHOLDER_SIZE,
            b"\x00",
        )

        self.assertEqual(
            len(padded),
            PDF_PLACEHOLDER_SIZE,
        )

        self.assertEqual(
            parse_cms_signed_data(padded),
            parse_cms_signed_data(self.cms),
        )

    def test_exact_content_info_and_detached_structure(self):
        parts = self.parts()

        content_info = parts["content_info"]
        fields = parts["fields"]
        signer = parts["signer"]

        self.assertEqual(
            [field.tag for field in content_info],
            [0x06, 0xa0],
        )

        self.assertEqual(
            content_info[0].raw,
            ID_SIGNED_DATA,
        )

        self.assertEqual(
            [field.tag for field in fields],
            [0x02, 0x31, 0x30, 0xa0, 0x31],
        )

        self.assertEqual(
            fields[0].raw,
            INTEGER_ONE,
        )

        # Exactly one eContentType, with no eContent field.
        self.assertEqual(
            fields[2].raw,
            sequence(ID_DATA),
        )

        self.assertEqual(
            [field.tag for field in signer],
            [0x02, 0x30, 0x30, 0xa0, 0x30, 0x04],
        )

        self.assertEqual(
            signer[0].raw,
            INTEGER_ONE,
        )

    def test_exact_algorithm_identifiers(self):
        parts = self.parts()

        fields = parts["fields"]
        signer = parts["signer"]

        self.assertEqual(
            fields[1].raw,
            set_of(SHA256_ABSENT),
        )

        self.assertEqual(
            signer[2].raw,
            SHA256_ABSENT,
        )

        self.assertEqual(
            signer[4].raw,
            RSA_NULL,
        )

    def test_embedded_certificate_and_signer_identifier(self):
        parts = self.parts()

        certificates = decode_implicit(
            parts["fields"][3],
            0,
            0x31,
        )

        self.assertEqual(len(certificates), 1)

        self.assertEqual(
            certificates[0].raw,
            self.certificate,
        )

        issuer, serial = decode_value(
            parts["signer"][1],
            0x30,
        )

        self.assertEqual(
            issuer.raw,
            self.parsed_certificate["issuer_der"],
        )

        self.assertEqual(
            decode_value(serial, 0x02),
            self.parsed_certificate["serial"],
        )

        self.assertEqual(
            serial.raw,
            integer(
                self.parsed_certificate["serial"]
            ),
        )

    def test_exact_mandatory_attributes_and_ordering(self):
        attrs = self.parts()["signer"][3]

        expected_der = set_of(
            self.content_attribute,
            self.digest_attribute,
            self.time_attribute,
        )

        self.assertEqual(
            attrs.raw,
            b"\xa0" + expected_der[1:],
        )

        children = decode_implicit(
            attrs,
            0,
            0x31,
        )

        self.assertEqual(len(children), 3)

        actual = [
            child.raw for child in children
        ]

        self.assertEqual(
            actual,
            sorted(self.default_attributes),
        )

    def test_signature_uses_universal_set_not_context_tag(self):
        parts = self.parts()

        attrs = parts["signer"][3]
        signature = decode_value(
            parts["signer"][5],
            0x04,
        )

        signed_attrs_der = (
            b"\x31" + attrs.raw[1:]
        )

        reference = pkcs1_15.new(
            self.key
        ).sign(
            SHA256.new(signed_attrs_der)
        )

        self.assertEqual(
            signature,
            reference,
        )

        public_key = self.key.public_key()

        pkcs1_15.new(public_key).verify(
            SHA256.new(signed_attrs_der),
            signature,
        )

        self.assertFalse(
            rsa_verify(
                public_key.export_key(),
                attrs.raw,
                signature,
            )
        )

        self.assertEqual(
            len(signature),
            384,
        )

    def test_builder_rejects_invalid_document_digests(self):
        for digest in (
            None,
            "",
            32,
            True,
            b"",
            bytes(31),
            bytes(33),
            bytearray(32),
            memoryview(bytes(32)),
        ):
            with self.subTest(
                input_type=type(digest).__name__
            ):
                with self.assertRaises(ValueError):
                    build_cms_signed_data(
                        digest,
                        self.certificate,
                        self.key,
                        self.signing_time,
                    )

    def test_builder_rejects_invalid_private_keys(self):
        for key in (
            None,
            123,
            self.key.public_key(),
            self.keys[2048],
            self.keys[4096],
        ):
            with self.subTest(
                key_type=type(key).__name__
            ):
                with self.assertRaises(ValueError):
                    build_cms_signed_data(
                        self.digest,
                        self.certificate,
                        key,
                        self.signing_time,
                    )

    def test_builder_rejects_certificate_key_mismatch(self):
        other_key = RSA.generate(3072)

        certificate = build_self_signed_certificate(
            other_key,
            "different_signer",
            self.start,
            self.end,
        )

        with self.assertRaisesRegex(
            ValueError,
            "does not match",
        ):
            build_cms_signed_data(
                self.digest,
                certificate,
                self.key,
                self.signing_time,
            )

    def test_builder_rejects_invalid_certificate_self_signature(self):
        modified = (
            self.certificate[:-1]
            + bytes([
                self.certificate[-1] ^ 1
            ])
        )

        parsed = parse_certificate(modified)

        self.assertFalse(
            rsa_verify(
                parsed["public_key_pem"],
                parsed["tbs_der"],
                parsed["signature"],
            )
        )

        with self.assertRaisesRegex(
            ValueError,
            "self-signature",
        ):
            build_cms_signed_data(
                self.digest,
                modified,
                self.key,
                self.signing_time,
            )

    def test_builder_rejects_malformed_certificates(self):
        values = (
            None,
            "",
            b"",
            b"\x30\x00",
            self.certificate[:-1],
            self.certificate + b"\x00",
        )

        for certificate in values:
            with self.subTest(
                input_type=type(certificate).__name__
            ):
                with self.assertRaises(ValueError):
                    build_cms_signed_data(
                        self.digest,
                        certificate,
                        self.key,
                        self.signing_time,
                    )

    def test_builder_rejects_invalid_signing_time(self):
        cases = (
            None,
            "2026-11-28",
            self.signing_time.replace(tzinfo=None),
            self.signing_time.replace(microsecond=1),
            self.signing_time.astimezone(
                timezone(timedelta(hours=7))
            ),
            datetime(
                1949, 12, 31,
                tzinfo=timezone.utc,
            ),
            datetime(
                2050, 1, 1,
                tzinfo=timezone.utc,
            ),
        )

        for signing_time in cases:
            with self.subTest(
                signing_time=signing_time
            ):
                with self.assertRaises(ValueError):
                    build_cms_signed_data(
                        self.digest,
                        self.certificate,
                        self.key,
                        signing_time,
                    )

    def test_builder_signing_time_validity_boundaries(self):
        for signing_time in (
            self.start,
            self.end,
        ):
            with self.subTest(
                signing_time=signing_time
            ):
                cms = build_cms_signed_data(
                    self.digest,
                    self.certificate,
                    self.key,
                    signing_time,
                )

                result = parse_cms_signed_data(cms)

                self.assertEqual(
                    result["signing_time"],
                    signing_time,
                )

                self.assertTrue(
                    self.verify_parsed(result)
                )

        for signing_time in (
            self.start - timedelta(seconds=1),
            self.end + timedelta(seconds=1),
        ):
            with self.subTest(
                signing_time=signing_time
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "outside certificate validity",
                ):
                    build_cms_signed_data(
                        self.digest,
                        self.certificate,
                        self.key,
                        signing_time,
                    )

    def test_builder_rejects_cms_exceeding_pdf_capacity(self):
        large_certificate = make_external_certificate(
            self.key,
            self.key,
            self_issued=True,
            extension_size=7500,
        )

        parsed = parse_certificate(
            large_certificate
        )

        self.assertTrue(
            rsa_verify(
                parsed["public_key_pem"],
                parsed["tbs_der"],
                parsed["signature"],
            )
        )

        with self.assertRaisesRegex(
            ValueError,
            "8192-byte",
        ):
            build_cms_signed_data(
                self.digest,
                large_certificate,
                self.key,
                self.signing_time,
            )

    # ========================================================
    # Successful CMS parsing
    # ========================================================

    def test_build_parse_verify_round_trip(self):
        parsed = parse_cms_signed_data(
            self.cms
        )

        self.assertEqual(
            parsed["certificate_der"],
            self.certificate,
        )

        self.assertEqual(
            parsed["message_digest"],
            SHA256.new(
                self.document
            ).digest(),
        )

        self.assertEqual(
            parsed["signing_time"],
            self.signing_time,
        )

        self.assertTrue(
            self.verify_parsed(parsed)
        )

    def test_exact_parser_return_dictionary_types(self):
        parsed = parse_cms_signed_data(
            self.cms
        )

        expected = {
            "certificate_der": bytes,
            "signed_attrs_der": bytes,
            "message_digest": bytes,
            "signing_time": datetime,
            "signature": bytes,
        }

        self.assertIs(type(parsed), dict)

        self.assertEqual(
            set(parsed),
            set(expected),
        )

        for key, value_type in expected.items():
            with self.subTest(field=key):
                self.assertIs(
                    type(parsed[key]),
                    value_type,
                )

        self.assertEqual(
            parsed["signing_time"].utcoffset(),
            timedelta(0),
        )

    def test_independent_fixture_and_raw_preservation(self):
        # Force long-form length encoding and include an
        # additional attribute. Reconstruction could omit it.
        extra = attribute(
            UNKNOWN_ATTR,
            wire(0x04, bytes(range(128))),
        )

        attributes = (
            *self.default_attributes,
            extra,
        )

        cms, expected_der, signature = self.fixture(
            attributes=attributes,
        )

        parsed = parse_cms_signed_data(cms)

        original = self.parts(cms)["signer"][3].raw

        self.assertEqual(original[0], 0xa0)

        self.assertTrue(
            original[1] & 0x80
        )

        self.assertEqual(
            parsed["signed_attrs_der"][0],
            0x31,
        )

        self.assertEqual(
            parsed["signed_attrs_der"][1:],
            original[1:],
        )

        self.assertEqual(
            parsed["signed_attrs_der"],
            expected_der,
        )

        self.assertEqual(
            parsed["certificate_der"],
            self.certificate,
        )

        self.assertEqual(
            parsed["signature"],
            signature,
        )

        self.assertTrue(
            self.verify_parsed(parsed)
        )

    def test_algorithm_null_and_absent_compatibility(self):
        for outer_digest in (
            SHA256_ABSENT,
            SHA256_NULL,
        ):
            for inner_digest in (
                SHA256_ABSENT,
                SHA256_NULL,
            ):
                for signature_algorithm in (
                    RSA_NULL,
                    RSA_ABSENT,
                    SHA256_RSA_NULL,
                    SHA256_RSA_ABSENT,
                ):
                    with self.subTest(
                        outer_digest=outer_digest.hex(),
                        inner_digest=inner_digest.hex(),
                        signature_algorithm=signature_algorithm.hex(),
                    ):
                        cms, _, _ = self.fixture(
                            digest_algorithm=outer_digest,
                            signer_digest_algorithm=inner_digest,
                            signature_algorithm=signature_algorithm,
                        )

                        parsed = parse_cms_signed_data(cms)

                        self.assertTrue(
                            self.verify_parsed(parsed)
                        )

    def test_external_certificates_and_supported_rsa_sizes(self):
        for bits, key in self.keys.items():
            with self.subTest(bits=bits):
                certificate = self.external_certificates[
                    bits
                ]

                cms, attrs, signature = self.fixture(
                    key=key,
                    certificate=certificate,
                )

                parsed = parse_cms_signed_data(cms)

                cert = parse_certificate(
                    parsed["certificate_der"]
                )

                public_key = RSA.import_key(
                    cert["public_key_pem"]
                )

                self.assertEqual(
                    public_key.size_in_bits(),
                    bits,
                )

                self.assertEqual(
                    parsed["signed_attrs_der"],
                    attrs,
                )

                self.assertEqual(
                    parsed["signature"],
                    signature,
                )

                self.assertEqual(
                    len(signature),
                    (bits + 7) // 8,
                )

                self.assertTrue(
                    self.verify_parsed(parsed)
                )

                # A CA-issued certificate need not verify
                # using its subject public key.
                self.assertFalse(
                    rsa_verify(
                        cert["public_key_pem"],
                        cert["tbs_der"],
                        cert["signature"],
                    )
                )

                issuer_key = self.keys[
                    4096 if bits == 2048 else 2048
                ].public_key()

                pkcs1_15.new(issuer_key).verify(
                    SHA256.new(cert["tbs_der"]),
                    cert["signature"],
                )

                pkcs1_15.new(public_key).verify(
                    SHA256.new(
                        parsed["signed_attrs_der"]
                    ),
                    parsed["signature"],
                )

    def test_valid_utc_and_generalized_signing_times(self):
        cases = (
            (
                wire(0x17, b"500101000000Z"),
                datetime(
                    1950, 1, 1,
                    tzinfo=timezone.utc,
                ),
            ),
            (
                wire(0x17, b"680101000000Z"),
                datetime(
                    1968, 1, 1,
                    tzinfo=timezone.utc,
                ),
            ),
            (
                wire(0x17, b"491231235959Z"),
                datetime(
                    2049, 12, 31, 23, 59, 59,
                    tzinfo=timezone.utc,
                ),
            ),
            (
                wire(0x18, b"20500101000000Z"),
                datetime(
                    2050, 1, 1,
                    tzinfo=timezone.utc,
                ),
            ),
            (
                wire(0x18, b"20261128123456Z"),
                self.signing_time,
            ),
        )

        for encoded, expected in cases:
            with self.subTest(
                signing_time=encoded
            ):
                cms, attrs, _ = self.fixture(
                    attributes=(
                        self.content_attribute,
                        self.digest_attribute,
                        attribute(
                            ATTR_SIGNING_TIME,
                            encoded,
                        ),
                    ),
                )

                parsed = parse_cms_signed_data(cms)

                self.assertEqual(
                    parsed["signing_time"],
                    expected,
                )

                self.assertEqual(
                    parsed["signed_attrs_der"],
                    attrs,
                )

                self.assertTrue(
                    self.verify_parsed(parsed)
                )

    # ========================================================
    # Attribute security validation
    # ========================================================

    def test_malformed_signing_time(self):
        cases = (
            wire(0x17, b"2611281234Z"),
            wire(0x17, b"261128123456+0700"),
            wire(0x17, b"260230123456Z"),
            wire(0x17, b"261128246000Z"),
            wire(0x18, b"20500230000000Z"),
            wire(0x18, b"20500101000000.5Z"),
            wire(0x18, b"20500101000000"),
            wire(0x0c, b"2026-11-28"),
            b"\x05\x00",
        )

        for encoded in cases:
            with self.subTest(encoded=encoded):
                self.assert_invalid(
                    attributes=(
                        self.content_attribute,
                        self.digest_attribute,
                        attribute(
                            ATTR_SIGNING_TIME,
                            encoded,
                        ),
                    ),
                )

    def test_missing_mandatory_attributes(self):
        # contentType and messageDigest are mandatory
        # whenever signedAttrs is present.
        self.assert_invalid(
            attributes=(
                self.digest_attribute,
                self.time_attribute,
            ),
        )

        self.assert_invalid(
            attributes=(
                self.content_attribute,
                self.time_attribute,
            ),
        )

        # signingTime is optional under CMS but required
        # by the Medimo verification profile.
        self.assert_unsupported(
            attributes=(
                self.content_attribute,
                self.digest_attribute,
            ),
        )

    def test_missing_and_empty_signed_attributes(self):
        self.assert_unsupported(
            include_attrs=False,
        )

        self.assert_invalid(
            attributes=(),
        )

    def test_duplicate_mandatory_attributes(self):
        for duplicate in (
            self.content_attribute,
            self.digest_attribute,
            self.time_attribute,
        ):
            with self.subTest(
                duplicate=duplicate.hex()
            ):
                self.assert_invalid(
                    attributes=(
                        *self.default_attributes,
                        duplicate,
                    ),
                )

    def test_invalid_attribute_cardinality(self):
        cases = (
            (
                ATTR_CONTENT_TYPE,
                ID_DATA,
            ),
            (
                ATTR_MESSAGE_DIGEST,
                wire(0x04, self.digest),
            ),
            (
                ATTR_SIGNING_TIME,
                self.time_value,
            ),
        )

        for oid, value in cases:
            other_attributes = tuple(
                encoded
                for encoded in self.default_attributes
                if not encoded.startswith(
                    sequence(oid)[:0] + b"\xff"
                )
            )

            # Remove the existing attribute of the same OID.
            other_attributes = tuple(
                encoded
                for encoded in other_attributes
                if decode_value(
                    parse_der(encoded),
                    0x30,
                )[0].raw != oid
            )

            for values in (
                (),
                (value, value),
            ):
                with self.subTest(
                    oid=oid.hex(),
                    cardinality=len(values),
                ):
                    self.assert_invalid(
                        attributes=(
                            *other_attributes,
                            attribute(
                                oid,
                                *values,
                            ),
                        ),
                    )

    def test_invalid_message_digest_length_and_type(self):
        cases = (
            wire(0x04, b""),
            wire(0x04, bytes(31)),
            wire(0x04, bytes(33)),
            wire(0x04, bytes(64)),
            wire(0x03, b"\x00" + self.digest),
            wire(0x0c, b"not a digest"),
        )

        for value in cases:
            with self.subTest(value=value.hex()):
                self.assert_invalid(
                    attributes=(
                        self.content_attribute,
                        self.time_attribute,
                        attribute(
                            ATTR_MESSAGE_DIGEST,
                            value,
                        ),
                    ),
                )

    def test_invalid_content_type_attribute(self):
        for value in (
            ID_SIGNED_DATA,
            b"\x05\x00",
            wire(0x04, b"data"),
        ):
            with self.subTest(value=value.hex()):
                self.assert_invalid(
                    attributes=(
                        self.digest_attribute,
                        self.time_attribute,
                        attribute(
                            ATTR_CONTENT_TYPE,
                            value,
                        ),
                    ),
                )

    def test_noncanonical_signed_attribute_ordering(self):
        attrs_wire = wire(
            0xa0,
            b"".join(
                sorted(
                    self.default_attributes,
                    reverse=True,
                )
            ),
        )

        cms, attrs_der, signature = self.fixture(
            attrs_wire=attrs_wire,
        )

        # Signature is mathematically valid over these bytes,
        # but the attributes violate canonical DER ordering.
        pkcs1_15.new(
            self.key.public_key()
        ).verify(
            SHA256.new(attrs_der),
            signature,
        )

        with self.assertRaises(
            InvalidSignatureError
        ):
            parse_cms_signed_data(cms)

    def test_noncanonical_attribute_value_set_ordering(self):
        unordered_values = wire(
            0x31,
            b"\x02\x01\x02"
            b"\x02\x01\x01",
        )

        extra = sequence(
            UNKNOWN_ATTR,
            unordered_values,
        )

        self.assert_invalid(
            attributes=(
                *self.default_attributes,
                extra,
            ),
        )

    def test_malformed_nested_signed_attributes(self):
        malformed_attributes = (
            b"\x30\x00",
            sequence(UNKNOWN_ATTR),
            sequence(
                UNKNOWN_ATTR,
                b"\x05\x00",
            ),
            sequence(
                UNKNOWN_ATTR,
                set_of(),
            ),
            sequence(
                UNKNOWN_ATTR,
                wire(
                    0x31,
                    b"\x30\x03\x02\x02\x01",
                ),
            ),
            sequence(
                UNKNOWN_ATTR,
                wire(
                    0x31,
                    b"\x01\x01\x01",
                ),
            ),
            sequence(
                UNKNOWN_ATTR,
                wire(
                    0x31,
                    nonminimal_wire(
                        0x04,
                        b"x",
                    ),
                ),
            ),
        )

        for malformed in malformed_attributes:
            with self.subTest(
                malformed=malformed.hex()
            ):
                self.assert_invalid(
                    attributes=(
                        *self.default_attributes,
                        malformed,
                    ),
                )

    # ========================================================
    # Algorithm and CMS profile validation
    # ========================================================

    def test_unsupported_digest_and_signature_algorithms(self):
        self.assert_unsupported(
            digest_algorithm=SHA384_ABSENT,
        )

        self.assert_unsupported(
            signer_digest_algorithm=SHA384_ABSENT,
        )

        self.assert_unsupported(
            signature_algorithm=SHA384_RSA_NULL,
        )

    def test_malformed_algorithm_parameters(self):
        sha256_oid = bytes.fromhex(
            "0609608648016503040201"
        )

        rsa_oid = bytes.fromhex(
            "06092a864886f70d010101"
        )

        bad_digest_algorithms = (
            b"\x30\x00",
            sequence(
                sha256_oid,
                b"\x02\x01\x00",
            ),
            sequence(
                sha256_oid,
                b"\x05\x01\x00",
            ),
            sequence(
                sha256_oid,
                b"\x05\x00",
                b"\x05\x00",
            ),
        )

        for algorithm in bad_digest_algorithms:
            with self.subTest(
                algorithm=algorithm.hex()
            ):
                self.assert_invalid(
                    digest_algorithm=algorithm,
                )

                self.assert_invalid(
                    signer_digest_algorithm=algorithm,
                )

        for algorithm in (
            sequence(
                rsa_oid,
                b"\x02\x01\x00",
            ),
            sequence(
                rsa_oid,
                b"\x05\x01\x00",
            ),
            sequence(
                rsa_oid,
                b"\x05\x00",
                b"\x05\x00",
            ),
        ):
            with self.subTest(
                algorithm=algorithm.hex()
            ):
                self.assert_invalid(
                    signature_algorithm=algorithm,
                )

    def test_mismatched_issuer_and_serial(self):
        certificate = self.parsed_certificate

        self.assert_unsupported(
            sid=sequence(
                name("Wrong Issuer"),
                integer(certificate["serial"]),
            ),
        )

        self.assert_unsupported(
            sid=sequence(
                certificate["issuer_der"],
                integer(
                    certificate["serial"] + 1
                ),
            ),
        )

    def test_malformed_signer_identifier(self):
        issuer = self.parsed_certificate[
            "issuer_der"
        ]

        for sid in (
            b"\x30\x00",
            sequence(issuer),
            sequence(
                issuer,
                b"\x02\x01\x00",
            ),
            sequence(
                issuer,
                b"\x02\x01\xff",
            ),
            sequence(
                issuer,
                b"\x02\x02\x00\x01",
            ),
            sequence(
                b"\x30\x02\x31\x00",
                INTEGER_ONE,
            ),
        ):
            with self.subTest(sid=sid.hex()):
                self.assert_invalid(sid=sid)

    def test_unsupported_subject_key_identifier(self):
        self.assert_unsupported(
            si_version=integer(3),
            sid=wire(
                0x80,
                bytes(range(20)),
            ),
        )

    def test_multiple_or_missing_certificates(self):
        self.assert_unsupported(
            certificate_set=wire(
                0xa0,
                b"".join(
                    sorted((
                        self.certificate,
                        self.external_certificates[2048],
                    ))
                ),
            ),
        )

        self.assert_unsupported(
            certificate_set=b"\xa0\x00",
        )

        self.assert_unsupported(
            include_certificates=False,
        )

    def test_multiple_or_missing_signers(self):
        signer = self.parts()[
            "signer_element"
        ].raw

        self.assert_unsupported(
            signer_set=set_of(
                signer,
                signer,
            ),
        )

        self.assert_unsupported(
            signer_set=b"\x31\x00",
        )

    def test_attached_and_unsupported_content_types(self):
        self.assert_unsupported(
            encap=sequence(
                ID_DATA,
                wire(
                    0xa0,
                    wire(
                        0x04,
                        self.document,
                    ),
                ),
            ),
        )

        self.assert_unsupported(
            encap=sequence(
                ID_SIGNED_DATA
            ),
        )

        self.assert_unsupported(
            content_type=ID_DATA,
        )

        self.assert_invalid(
            encap=sequence(
                ID_DATA,
                wire(
                    0xa0,
                    b"\x05\x00",
                ),
            ),
        )

    def test_cms_version_validation(self):
        self.assert_unsupported(
            sd_version=integer(3),
        )

        self.assert_unsupported(
            si_version=integer(3),
        )

        for version in (
            integer(-1),
            integer(6),
            b"\x02\x02\x00\x01",
            b"\x05\x00",
        ):
            with self.subTest(
                version=version.hex()
            ):
                self.assert_invalid(
                    sd_version=version,
                )

                self.assert_invalid(
                    si_version=version,
                )

    def test_unsupported_optional_cms_fields(self):
        unsigned = wire(
            0xa1,
            attribute(
                UNKNOWN_ATTR,
                b"\x05\x00",
            ),
        )

        self.assert_unsupported(
            unsigned_attrs=unsigned,
        )

        self.assert_invalid(
            unsigned_attrs=b"\xa1\x00",
        )

        self.assert_invalid(
            unsigned_attrs=b"\xa2\x00",
        )

        self.assert_invalid(
            crls=b"\xa1\x00",
        )

    def test_invalid_signature_octet_string(self):
        for signature_value in (
            b"\x04\x00",
            b"\x03\x02\x00\x01",
            b"\x05\x00",
            b"\x04\x02\x01",
        ):
            with self.subTest(
                signature_value=signature_value.hex()
            ):
                self.assert_invalid(
                    signature_value=signature_value,
                )

    # ========================================================
    # DER error classification and PDF Contents handling
    # ========================================================

    def test_malformed_embedded_certificate(self):
        # Pass an independent valid sid so fixture construction
        # does not attempt to parse the deliberately broken cert.
        sid = sequence(
            self.parsed_certificate["issuer_der"],
            integer(
                self.parsed_certificate["serial"]
            ),
        )

        cases = (
            b"\x30\x00",
            self.certificate[:-1],
            self.certificate + b"\x00",
        )

        for certificate in cases:
            with self.subTest(
                length=len(certificate)
            ):
                self.assert_invalid(
                    certificate=certificate,
                    sid=sid,
                )

    def test_outer_indefinite_length_before_padding_validation(self):
        root = parse_der(self.cms)

        indefinite = indefinite_wire(
            0x30,
            root.value,
        )

        for contents in (
            indefinite,
            indefinite + b"\x00" * 100,
            indefinite + b"\xff",
        ):
            with self.subTest(
                length=len(contents)
            ):
                with self.assertRaises(
                    UnsupportedSignatureError
                ) as caught:
                    parse_cms_signed_data(contents)

                self.assertIsInstance(
                    caught.exception.__cause__,
                    DerError,
                )

                self.assertEqual(
                    caught.exception.__cause__.kind,
                    "non_der",
                )

    def test_outer_nonminimal_length_is_unsupported(self):
        parts = self.parts()

        cases = (
            nonminimal_wire(
                0x30,
                parts["root"].value,
            ),
            sequence(
                ID_SIGNED_DATA,
                wire(
                    0xa0,
                    nonminimal_wire(
                        0x30,
                        parts["signed_data"].value,
                    ),
                ),
            ),
        )

        for contents in cases:
            with self.subTest(
                length=len(contents)
            ):
                with self.assertRaises(
                    UnsupportedSignatureError
                ):
                    parse_cms_signed_data(contents)

    def test_signer_info_nonminimal_header_is_unsupported(self):
        signer = self.parts()[
            "signer_element"
        ]

        self.assert_unsupported(
            signer_set=wire(
                0x31,
                nonminimal_wire(
                    0x30,
                    signer.value,
                ),
            ),
        )

    def test_signed_attrs_nonminimal_or_indefinite_header_is_invalid(self):
        content = b"".join(
            sorted(self.default_attributes)
        )

        for attrs_wire in (
            nonminimal_wire(
                0xa0,
                content,
            ),
            indefinite_wire(
                0xa0,
                content,
            ),
        ):
            with self.subTest(
                header=attrs_wire[:5].hex()
            ):
                cms, _, _ = self.fixture(
                    attrs_wire=attrs_wire,
                )

                with self.assertRaises(
                    InvalidSignatureError
                ) as caught:
                    parse_cms_signed_data(cms)

                self.assertIsInstance(
                    caught.exception.__cause__,
                    DerError,
                )

                self.assertEqual(
                    caught.exception.__cause__.kind,
                    "non_der",
                )

    def test_certificate_nonminimal_or_indefinite_header_is_invalid(self):
        content = parse_der(
            self.certificate
        ).value

        for certificate_wire in (
            nonminimal_wire(
                0x30,
                content,
            ),
            indefinite_wire(
                0x30,
                content,
            ),
        ):
            with self.subTest(
                header=certificate_wire[:5].hex()
            ):
                cms, _, _ = self.fixture(
                    certificate_set=wire(
                        0xa0,
                        certificate_wire,
                    ),
                )

                with self.assertRaises(
                    InvalidSignatureError
                ) as caught:
                    parse_cms_signed_data(cms)

                self.assertIsInstance(
                    caught.exception.__cause__,
                    DerError,
                )

                self.assertEqual(
                    caught.exception.__cause__.kind,
                    "non_der",
                )

    def test_nested_certificate_non_der_is_invalid(self):
        root = parse_der(
            self.certificate
        )

        tbs, algorithm, signature = decode_value(
            root,
            0x30,
        )

        malformed_certificate = sequence(
            nonminimal_wire(
                0x30,
                tbs.value,
            ),
            algorithm.raw,
            signature.raw,
        )

        self.assert_invalid(
            certificate_set=wire(
                0xa0,
                malformed_certificate,
            ),
        )

    def test_malformed_outer_structure_and_truncation(self):
        parts = self.parts()

        cases = (
            b"",
            b"\x30",
            b"\x30\x00",
            self.cms[:4],
            self.cms[:-1],
            wire(
                0x04,
                self.cms,
            ),
            sequence(ID_SIGNED_DATA),
            sequence(
                ID_SIGNED_DATA,
                wire(0xa0, b""),
            ),
            sequence(
                ID_SIGNED_DATA,
                wire(
                    0xa0,
                    parts["signed_data"].raw
                    + b"\x05\x00",
                ),
            ),
        )

        for contents in cases:
            with self.subTest(
                length=len(contents)
            ):
                with self.assertRaises(
                    InvalidSignatureError
                ):
                    parse_cms_signed_data(contents)

    def test_zero_padding_and_exact_tlv_boundary(self):
        expected = parse_cms_signed_data(
            self.cms
        )

        for padding in (
            0,
            1,
            2,
            128,
            PDF_PLACEHOLDER_SIZE - len(self.cms),
        ):
            with self.subTest(padding=padding):
                contents = (
                    self.cms
                    + b"\x00" * padding
                )

                self.assertEqual(
                    parse_cms_signed_data(contents),
                    expected,
                )

        # A signature OCTET STRING may itself end in zero.
        # Parsing must preserve it rather than rstrip zeros.
        original = expected["signature"]

        modified = (
            original[:-1] + b"\x00"
        )

        cms, _, _ = self.fixture(
            signature_override=modified,
        )

        parsed = parse_cms_signed_data(
            cms + b"\x00" * 20
        )

        self.assertEqual(
            parsed["signature"],
            modified,
        )

        self.assertEqual(
            len(parsed["signature"]),
            len(original),
        )

    def test_nonzero_trailing_bytes_are_invalid(self):
        for trailing in (
            b"\x01",
            b"\x00\x00\xff",
            b"\x05\x00",
            b"\x00" * 10 + self.cms,
        ):
            with self.subTest(
                length=len(trailing)
            ):
                with self.assertRaises(
                    InvalidSignatureError
                ):
                    parse_cms_signed_data(
                        self.cms + trailing
                    )

    def test_invalid_parser_input_types(self):
        for value in (
            None,
            "",
            "CMS",
            123,
            True,
            bytearray(self.cms),
            memoryview(self.cms),
        ):
            with self.subTest(
                input_type=type(value).__name__
            ):
                with self.assertRaises(
                    InvalidSignatureError
                ):
                    parse_cms_signed_data(value)

    # ========================================================
    # Stage 7c: Resource-limit tests
    # ========================================================

    def assert_resource_error(self, cms):
        with self.assertRaises(
            InvalidSignatureError
        ) as caught:
            parse_cms_signed_data(cms)

        cause = caught.exception.__cause__

        self.assertIsInstance(
            cause,
            DerError,
        )

        self.assertEqual(
            cause.kind,
            "malformed",
        )

        self.assertEqual(
            cause.reason,
            "resource_limit",
        )

    def test_parser_input_size_limit(self):
        # An external PDF may have a larger zero-filled slot.
        # The DER decoder's input bound remains authoritative.
        exact = self.cms.ljust(
            MAX_INPUT_SIZE,
            b"\x00",
        )

        self.assertEqual(
            len(exact),
            MAX_INPUT_SIZE,
        )

        self.assertEqual(
            parse_cms_signed_data(exact),
            parse_cms_signed_data(self.cms),
        )

        self.assert_resource_error(
            exact + b"\x00"
        )

    def test_parser_element_length_limit(self):
        oversized = wire(
            0x30,
            b"\x00" * (
                MAX_ELEMENT_LENGTH + 1
            ),
        )

        self.assert_resource_error(
            oversized
        )

    def test_parser_nested_depth_limit(self):
        nested = b"\x05\x00"

        for _ in range(MAX_DEPTH):
            nested = wire(
                0x30,
                nested,
            )

        extra = attribute(
            UNKNOWN_ATTR,
            nested,
        )

        cms, _, _ = self.fixture(
            attributes=(
                *self.default_attributes,
                extra,
            ),
        )

        self.assert_resource_error(cms)

    def test_parser_child_count_limit(self):
        extra = attribute(
            UNKNOWN_ATTR,
            wire(
                0x30,
                b"\x05\x00" * (
                    MAX_CHILDREN + 1
                ),
            ),
        )

        cms, _, _ = self.fixture(
            attributes=(
                *self.default_attributes,
                extra,
            ),
        )

        self.assert_resource_error(cms)

    def test_parser_total_element_budget(self):
        groups = []

        count = (
            MAX_TOTAL_ELEMENTS // 16
        ) + 1

        self.assertLessEqual(
            count,
            MAX_CHILDREN,
        )

        for _ in range(16):
            groups.append(
                wire(
                    0x30,
                    b"\x05\x00" * count,
                )
            )

        extra = attribute(
            UNKNOWN_ATTR,
            sequence(*groups),
        )

        cms, _, _ = self.fixture(
            attributes=(
                *self.default_attributes,
                extra,
            ),
        )

        self.assert_resource_error(cms)

    # ========================================================
    # Structural validity is not cryptographic validity
    # ========================================================

    def test_tampered_signed_attributes_parse_but_fail_verification(self):
        original = parse_cms_signed_data(
            self.cms
        )

        modified_digest = (
            self.digest[:-1]
            + bytes([
                self.digest[-1] ^ 1
            ])
        )

        cms, _, _ = self.fixture(
            attributes=(
                self.content_attribute,
                self.time_attribute,
                attribute(
                    ATTR_MESSAGE_DIGEST,
                    wire(
                        0x04,
                        modified_digest,
                    ),
                ),
            ),
            signature_override=original[
                "signature"
            ],
        )

        parsed = parse_cms_signed_data(cms)

        self.assertEqual(
            parsed["message_digest"],
            modified_digest,
        )

        self.assertNotEqual(
            parsed["signed_attrs_der"],
            original["signed_attrs_der"],
        )

        self.assertEqual(
            parsed["signature"],
            original["signature"],
        )

        self.assertFalse(
            self.verify_parsed(parsed)
        )

    def test_tampered_signature_parses_but_fails_verification(self):
        original = parse_cms_signed_data(
            self.cms
        )

        signature = original["signature"]

        modified = (
            signature[:-1]
            + bytes([signature[-1] ^ 1])
        )

        cms, _, _ = self.fixture(
            signature_override=modified,
        )

        parsed = parse_cms_signed_data(cms)

        self.assertEqual(
            parsed["signed_attrs_der"],
            original["signed_attrs_der"],
        )

        self.assertEqual(
            parsed["signature"],
            modified,
        )

        self.assertFalse(
            self.verify_parsed(parsed)
        )

    def test_wrong_document_digest_is_not_checked_by_parser(self):
        different_document = (
            self.document + b"modified"
        )

        different_digest = SHA256.new(
            different_document
        ).digest()

        cms, _, _ = self.fixture(
            attributes=(
                self.content_attribute,
                self.time_attribute,
                attribute(
                    ATTR_MESSAGE_DIGEST,
                    wire(
                        0x04,
                        different_digest,
                    ),
                ),
            ),
        )

        parsed = parse_cms_signed_data(cms)

        # The CMS signature is valid for its signed attributes.
        self.assertTrue(
            self.verify_parsed(parsed)
        )

        # But it does not authenticate the original document.
        self.assertNotEqual(
            parsed["message_digest"],
            SHA256.new(
                self.document
            ).digest(),
        )

    def test_signing_time_validity_is_not_checked_by_parser(self):
        cms, _, _ = self.fixture(
            attributes=(
                self.content_attribute,
                self.digest_attribute,
                attribute(
                    ATTR_SIGNING_TIME,
                    wire(
                        0x17,
                        b"490101000000Z",
                    ),
                ),
            ),
        )

        parsed = parse_cms_signed_data(cms)

        certificate = parse_certificate(
            parsed["certificate_der"]
        )

        self.assertTrue(
            self.verify_parsed(parsed)
        )

        self.assertGreater(
            parsed["signing_time"],
            certificate["not_after"],
        )

    # ========================================================
    # Independent OpenSSL interoperability
    # ========================================================

    @unittest.skipUnless(
        shutil.which("openssl"),
        "OpenSSL unavailable",
    )
    def test_openssl_generated_cms_inspection_and_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            cms_path = root / "signature.der"
            document_path = root / "document.bin"
            output_path = root / "verified.bin"

            cms_path.write_bytes(self.cms)

            document_path.write_bytes(
                self.document
            )

            inspection = self.run_openssl(
                "cms",
                "-cmsout",
                "-print",
                "-inform", "DER",
                "-in", str(cms_path),
            )

            self.assert_openssl_success(
                inspection
            )

            self.assertIn(
                b"pkcs7-signedData",
                inspection.stdout,
            )

            self.assertIn(
                b"sha256",
                inspection.stdout,
            )

            self.assertIn(
                b"rsaEncryption",
                inspection.stdout,
            )

            verified = self.run_openssl(
                "cms",
                "-verify",
                "-binary",
                "-inform", "DER",
                "-in", str(cms_path),
                "-content", str(document_path),
                "-noverify",
                "-out", str(output_path),
            )

            self.assert_openssl_success(
                verified
            )

            self.assertEqual(
                output_path.read_bytes(),
                self.document,
            )

            # Alter the original detached content.
            document_path.write_bytes(
                self.document + b"\x00"
            )

            rejected = self.run_openssl(
                "cms",
                "-verify",
                "-binary",
                "-inform", "DER",
                "-in", str(cms_path),
                "-content", str(document_path),
                "-noverify",
                "-out", str(output_path),
            )

            self.assertNotEqual(
                rejected.returncode,
                0,
            )

    @unittest.skipUnless(
        shutil.which("openssl"),
        "OpenSSL unavailable",
    )
    def test_parse_and_verify_independently_generated_openssl_cms(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            cert_path = root / "certificate.pem"
            key_path = root / "private.pem"
            document_path = root / "document.bin"
            cms_path = root / "openssl-signature.der"

            # Certificate and private key are dummy fixtures
            # created exclusively for this test.
            from base64 import encodebytes

            cert_path.write_bytes(
                b"-----BEGIN CERTIFICATE-----\n"
                + encodebytes(self.certificate)
                + b"-----END CERTIFICATE-----\n"
            )

            key_path.write_bytes(
                self.key.export_key(
                    format="PEM",
                    pkcs=8,
                )
            )

            document_path.write_bytes(
                self.document
            )

            result = self.run_openssl(
                "cms",
                "-sign",
                "-binary",
                "-in", str(document_path),
                "-signer", str(cert_path),
                "-inkey", str(key_path),
                "-md", "sha256",
                "-outform", "DER",
                "-out", str(cms_path),
            )

            self.assert_openssl_success(result)

            external_cms = cms_path.read_bytes()

            parsed = parse_cms_signed_data(
                external_cms
            )

            self.assertEqual(
                parsed["certificate_der"],
                self.certificate,
            )

            self.assertEqual(
                parsed["message_digest"],
                self.digest,
            )

            self.assertTrue(
                self.verify_parsed(parsed)
            )

            # Independent reference verification over the
            # exact signedAttrs bytes returned by our parser.
            pkcs1_15.new(
                self.key.public_key()
            ).verify(
                SHA256.new(
                    parsed["signed_attrs_der"]
                ),
                parsed["signature"],
            )


if __name__ == "__main__":
    unittest.main()