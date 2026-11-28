import shutil
import subprocess
import tempfile
import unittest

from pathlib import Path
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from Crypto.Hash import SHA256, SHA384
from Crypto.PublicKey import RSA, ECC
from Crypto.Signature import pkcs1_15

from certificate import (
    build_self_signed_certificate,
    parse_certificate,
)

from der import (
    DerError,
    MAX_INPUT_SIZE,
    MAX_ELEMENT_LENGTH,
    MAX_DEPTH,
    MAX_CHILDREN,
    MAX_TOTAL_ELEMENTS,
    decode_explicit,
    decode_value,
    parse_der,
    validate_tree,
)

from share_errors import (
    InvalidSignatureError,
    UnsupportedSignatureError,
)

from signing_keys import rsa_sign, rsa_verify


# ============================================================
# Stage 4a: Existing certificate builder tests
# ============================================================


class TestCertificateBuilder(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key = RSA.generate(3072)
        cls.username = "alice_01"

        cls.start = datetime(
            2028, 2, 29,
            12, 34, 56,
            tzinfo=timezone.utc,
        )

        cls.end = cls.start + timedelta(days=730)

        cls.cert = build_self_signed_certificate(
            cls.key,
            cls.username,
            cls.start,
            cls.end,
        )

        cls.outer = decode_value(
            validate_tree(parse_der(cls.cert)),
            0x30,
        )

        cls.tbs = cls.outer[0]

        cls.fields = decode_value(
            cls.tbs,
            0x30,
        )

    def build(
        self,
        username=None,
        start=None,
        end=None,
        key=None,
    ):
        return build_self_signed_certificate(
            self.key if key is None else key,
            self.username if username is None else username,
            self.start if start is None else start,
            self.end if end is None else end,
        )

    def fields_of(self, cert):
        tbs, _, _ = decode_value(
            parse_der(cert),
            0x30,
        )

        return decode_value(tbs, 0x30)

    def extensions(self):
        return decode_value(
            decode_explicit(self.fields[7], 3),
            0x30,
        )

    def test_successful_generation(self):
        self.assertIsInstance(self.cert, bytes)
        self.assertLess(len(self.cert), 8192)

        self.assertEqual(
            parse_der(self.cert).raw,
            self.cert,
        )

    def test_exact_structure(self):
        self.assertEqual(
            [e.tag for e in self.outer],
            [0x30, 0x30, 0x03],
        )

        self.assertEqual(
            [e.tag for e in self.fields],
            [
                0xa0,
                0x02,
                0x30,
                0x30,
                0x30,
                0x30,
                0x30,
                0xa3,
            ],
        )

        self.assertEqual(
            len(self.extensions()),
            2,
        )

    def test_version(self):
        self.assertEqual(
            self.fields[0].raw,
            bytes.fromhex("a003020102"),
        )

        self.assertEqual(
            decode_value(
                decode_explicit(self.fields[0], 0),
                0x02,
            ),
            2,
        )

    def test_serial_positive_minimal(self):
        serial = decode_value(
            self.fields[1],
            0x02,
        )

        self.assertTrue(
            0 < serial < (1 << 127)
        )

        cases = [
            (
                b"\x00" * 15 + b"\x01",
                "020101",
            ),
            (
                b"\x00" * 15 + b"\x80",
                "02020080",
            ),
            (
                b"\xff" * 16,
                "02107f" + "ff" * 15,
            ),
        ]

        for random_bytes, expected in cases:
            with self.subTest(expected=expected):

                with patch(
                    "certificate.get_random_bytes",
                    return_value=random_bytes,
                ) as rng:

                    fields = self.fields_of(
                        self.build()
                    )

                rng.assert_called_once_with(16)

                self.assertEqual(
                    fields[1].raw,
                    bytes.fromhex(expected),
                )

    def test_retry_zero_serial(self):
        with patch(
            "certificate.get_random_bytes",
            side_effect=[
                b"\x00" * 16,
                b"\x80" + b"\x00" * 15,
                b"\x00" * 15 + b"\x01",
            ],
        ) as rng:

            fields = self.fields_of(
                self.build()
            )

        self.assertEqual(
            [c.args for c in rng.call_args_list],
            [(16,), (16,), (16,)],
        )

        self.assertEqual(
            fields[1].raw,
            bytes.fromhex("020101"),
        )

    def test_issuer_subject_identical(self):
        self.assertEqual(
            self.fields[3].raw,
            self.fields[5].raw,
        )

    def test_name_exact_encoding(self):
        expected = bytes.fromhex(
            "3024"
            "310f"
            "300d"
            "060355040a"
            "0c064d6564696d6f"
            "3111"
            "300f"
            "0603550403"
            "0c08616c6963655f3031"
        )

        self.assertEqual(
            self.fields[3].raw,
            expected,
        )

    def test_unicode_and_underscore(self):
        fields = self.fields_of(
            self.build(username="é_用户")
        )

        rdns = decode_value(
            fields[5],
            0x30,
        )

        attribute, = decode_value(
            rdns[1],
            0x31,
        )

        oid, value = decode_value(
            attribute,
            0x30,
        )

        self.assertEqual(
            decode_value(oid, 0x06),
            "2.5.4.3",
        )

        self.assertEqual(
            value.raw,
            bytes.fromhex(
                "0c09c3a95fe794a8e688b7"
            ),
        )

        self.assertEqual(
            decode_value(value, 0x0c),
            "é_用户",
        )

    def test_invalid_username(self):
        values = (
            None,
            7,
            b"alice",
            "",
            "   ",
            "a\x00b",
            "\ud800",
            "a" * 65,
            "é" * 65,
        )

        for username in values:
            with self.subTest(
                username=repr(username)
            ):
                with self.assertRaises(ValueError):
                    build_self_signed_certificate(
                        self.key,
                        username,
                        self.start,
                        self.end,
                    )

    def test_common_name_boundary(self):
        username = "é" * 64

        fields = self.fields_of(
            self.build(username=username)
        )

        _, cn = decode_value(
            fields[5],
            0x30,
        )

        attribute, = decode_value(
            cn,
            0x31,
        )

        _, value = decode_value(
            attribute,
            0x30,
        )

        self.assertEqual(
            value.raw,
            b"\x0c\x81\x80" + b"\xc3\xa9" * 64,
        )

        self.assertEqual(
            decode_value(value, 0x0c),
            username,
        )

    def test_signature_algorithm(self):
        expected = bytes.fromhex(
            "300d06092a864886f70d01010b0500"
        )

        self.assertEqual(
            self.fields[2].raw,
            expected,
        )

        self.assertEqual(
            self.outer[1].raw,
            expected,
        )

    def test_subject_public_key_info(self):
        spki = self.fields[6].raw

        self.assertEqual(
            spki,
            self.key.public_key().export_key(
                format="DER"
            ),
        )

        imported = RSA.import_key(spki)

        self.assertFalse(
            imported.has_private()
        )

        self.assertEqual(
            (imported.n, imported.e),
            (self.key.n, self.key.e),
        )

    def test_validity_and_leap_year(self):
        expected_end = datetime(
            2030, 2, 28,
            12, 34, 56,
            tzinfo=timezone.utc,
        )

        self.assertEqual(
            self.end,
            expected_end,
        )

        self.assertEqual(
            self.fields[4].raw,
            b"\x30\x1e"
            b"\x17\x0d280229123456Z"
            b"\x17\x0d300228123456Z",
        )

        before, after = decode_value(
            self.fields[4],
            0x30,
        )

        self.assertEqual(
            decode_value(before, 0x17),
            self.start,
        )

        self.assertEqual(
            decode_value(after, 0x17),
            expected_end,
        )

    def test_utc_year_boundary(self):
        last = datetime(
            2049, 12, 31,
            23, 59, 59,
            tzinfo=timezone.utc,
        )

        fields = self.fields_of(
            self.build(
                start=last - timedelta(days=730),
                end=last,
            )
        )

        _, after = decode_value(
            fields[4],
            0x30,
        )

        self.assertEqual(
            after.raw,
            b"\x17\x0d491231235959Z",
        )

        first = datetime(
            1950, 1, 1,
            tzinfo=timezone.utc,
        )

        fields = self.fields_of(
            self.build(
                start=first,
                end=first + timedelta(days=730),
            )
        )

        before, _ = decode_value(
            fields[4],
            0x30,
        )

        self.assertEqual(
            before.raw,
            b"\x17\x0d500101000000Z",
        )

        for start in (
            last - timedelta(days=729),
            first - timedelta(days=1),
        ):
            with self.assertRaises(ValueError):
                self.build(
                    start=start,
                    end=start + timedelta(days=730),
                )

    def test_basic_constraints_exact(self):
        bc, _ = self.extensions()

        self.assertEqual(
            bc.raw,
            bytes.fromhex(
                "300c0603551d130101ff04023000"
            ),
        )

        _, _, value = decode_value(
            bc,
            0x30,
        )

        self.assertEqual(
            decode_value(value, 0x04),
            b"\x30\x00",
        )

    def test_key_usage_exact(self):
        _, ku = self.extensions()

        self.assertEqual(
            ku.raw,
            bytes.fromhex(
                "300e0603551d0f0101ff0404030206c0"
            ),
        )

        _, _, value = decode_value(
            ku,
            0x30,
        )

        inner = parse_der(
            decode_value(value, 0x04)
        )

        self.assertEqual(
            decode_value(inner, 0x03),
            (b"\xc0", 6),
        )

    def test_critical_boolean(self):
        for extension in self.extensions():
            _, critical, _ = decode_value(
                extension,
                0x30,
            )

            self.assertEqual(
                critical.raw,
                bytes.fromhex("0101ff"),
            )

            self.assertIs(
                decode_value(critical, 0x01),
                True,
            )

        self.assertEqual(
            self.fields[7].raw,
            bytes.fromhex(
                "a320301e"
                "300c0603551d130101ff04023000"
                "300e0603551d0f0101ff0404030206c0"
            ),
        )

    def test_signature_medimo_verifier(self):
        signature, unused = decode_value(
            self.outer[2],
            0x03,
        )

        self.assertEqual(unused, 0)
        self.assertEqual(len(signature), 384)

        pem = self.key.public_key().export_key(
            format="PEM"
        )

        self.assertTrue(
            rsa_verify(
                pem,
                self.tbs.raw,
                signature,
            )
        )

        self.assertFalse(
            rsa_verify(
                pem,
                self.tbs.raw + b"\x00",
                signature,
            )
        )

    def test_signature_independent_reference(self):
        signature, _ = decode_value(
            self.outer[2],
            0x03,
        )

        digest = SHA256.new(self.tbs.raw)

        pkcs1_15.new(
            self.key.public_key()
        ).verify(
            digest,
            signature,
        )

        self.assertEqual(
            signature,
            pkcs1_15.new(self.key).sign(digest),
        )

    def test_invalid_private_keys(self):
        small_key = RSA.generate(2048)

        values = (
            None,
            7,
            b"not a key",
            self.key.public_key(),
            small_key,
        )

        for key in values:
            with self.subTest(
                key_type=type(key).__name__
            ):
                with self.assertRaises(ValueError):
                    build_self_signed_certificate(
                        key,
                        self.username,
                        self.start,
                        self.end,
                    )

    def test_invalid_datetime_inputs(self):
        values = (
            None,
            "2028-02-29",
            self.start.replace(tzinfo=None),
            self.start.astimezone(
                timezone(timedelta(hours=7))
            ),
            self.start.replace(microsecond=1),
        )

        for value in values:
            for before, after in (
                (value, self.end),
                (self.start, value),
            ):
                with self.subTest(
                    value=value,
                    before=before,
                ):
                    with self.assertRaises(ValueError):
                        build_self_signed_certificate(
                            self.key,
                            self.username,
                            before,
                            after,
                        )

    def test_invalid_validity_duration(self):
        for days in (-1, 0, 729, 731):
            with self.subTest(days=days):
                with self.assertRaises(ValueError):
                    self.build(
                        end=self.start
                        + timedelta(days=days)
                    )

        with self.assertRaises(ValueError):
            self.build(
                end=self.end
                + timedelta(seconds=1)
            )

    @unittest.skipUnless(
        shutil.which("openssl"),
        "OpenSSL unavailable",
    )
    def test_openssl_inspection(self):
        result = subprocess.run(
            [
                "openssl",
                "x509",
                "-inform",
                "DER",
                "-noout",
                "-text",
            ],
            input=self.cert,
            capture_output=True,
            timeout=10,
            check=True,
        )

        self.assertIn(
            b"Version: 3",
            result.stdout,
        )

        self.assertIn(
            b"sha256WithRSAEncryption",
            result.stdout,
        )

        self.assertIn(
            b"CA:FALSE",
            result.stdout,
        )

        self.assertIn(
            b"Digital Signature",
            result.stdout,
        )

        self.assertTrue(
            b"Non Repudiation" in result.stdout
            or b"Content Commitment" in result.stdout
        )


# ============================================================
# Stage 4b: Independent DER fixture helpers
# ============================================================


_SIG_NULL = bytes.fromhex(
    "300d06092a864886f70d01010b0500"
)

_SIG_ABSENT = bytes.fromhex(
    "300b06092a864886f70d01010b"
)

_SIG_SHA384 = bytes.fromhex(
    "300d06092a864886f70d01010c0500"
)

_RSA_NULL = bytes.fromhex(
    "300d06092a864886f70d0101010500"
)

_RSA_ABSENT = bytes.fromhex(
    "300b06092a864886f70d010101"
)

_CN_OID = bytes.fromhex("0603550403")
_ORG_OID = bytes.fromhex("060355040a")

_BC_OID = bytes.fromhex("0603551d13")
_KU_OID = bytes.fromhex("0603551d0f")

_UNKNOWN_OID = bytes.fromhex("06032a0304")

_VERSION_3 = bytes.fromhex("a003020102")


def _wire(tag, content):
    """Independent TLV construction for test fixtures."""

    size = len(content)

    if size < 128:
        length = bytes([size])
    else:
        count = (size.bit_length() + 7) // 8

        length = (
            bytes([0x80 | count])
            + size.to_bytes(count, "big")
        )

    return bytes([tag]) + length + content


def _positive_integer(value):
    raw = value.to_bytes(
        max(1, (value.bit_length() + 7) // 8),
        "big",
    )

    if raw[0] & 0x80:
        raw = b"\x00" + raw

    return _wire(0x02, raw)


def _attribute(oid, string_tag, value):
    return _wire(
        0x30,
        oid + _wire(string_tag, value),
    )


def _name(cn, *, tag=0x0c):
    if isinstance(cn, str):
        cn = cn.encode("utf-8")

    organization = _attribute(
        _ORG_OID,
        0x0c,
        b"External Organization",
    )

    common_name = _attribute(
        _CN_OID,
        tag,
        cn,
    )

    return _wire(
        0x30,
        _wire(0x31, organization)
        + _wire(0x31, common_name),
    )


def _validity(before, after):
    return _wire(
        0x30,
        before + after,
    )


def _spki(n, e, algorithm=_RSA_NULL):
    public_key = _wire(
        0x30,
        _positive_integer(n)
        + _positive_integer(e),
    )

    return _wire(
        0x30,
        algorithm
        + _wire(0x03, b"\x00" + public_key),
    )


def _extension(
    oid,
    value,
    *,
    critical=False,
):
    flag = b"\x01\x01\xff" if critical else b""

    return _wire(
        0x30,
        oid
        + flag
        + _wire(0x04, value),
    )


def _extensions(*values):
    return _wire(
        0xa3,
        _wire(0x30, b"".join(values)),
    )


# ============================================================
# Stage 4b: Existing certificate parser tests
# ============================================================


class TestCertificateParser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.key2048 = RSA.generate(2048)
        cls.key3072 = RSA.generate(3072)
        cls.key4096 = RSA.generate(4096)

        cls.start = datetime(
            2026, 1, 1,
            tzinfo=timezone.utc,
        )

        cls.end = cls.start + timedelta(days=730)

        cls.medimo_cert = build_self_signed_certificate(
            cls.key3072,
            "alice_01",
            cls.start,
            cls.end,
        )

        cls.issuer = _name(
            b"Example CA",
            tag=0x13,
        )

        cls.subject = _name(
            "external_user"
        )

        cls.validity = _validity(
            b"\x17\x0d260101000000Z",
            b"\x17\x0d270101000000Z",
        )

        cls.basic_constraints = _extension(
            _BC_OID,
            b"\x30\x00",
            critical=True,
        )

        cls.key_usage = _extension(
            _KU_OID,
            bytes.fromhex("030206c0"),
            critical=True,
        )

    def fixture(
        self,
        *,
        key=None,
        issuer_key=None,
        version=_VERSION_3,
        serial=b"\x02\x02\x00\x80",
        inner_algorithm=_SIG_NULL,
        outer_algorithm=None,
        issuer=None,
        subject=None,
        validity=None,
        spki=None,
        optional=b"",
        signature_value=None,
        hashmod=SHA256,
    ):
        """Build a certificate independently of production builder."""

        key = (
            self.key3072
            if key is None
            else key
        )

        issuer_key = (
            self.key2048
            if issuer_key is None
            else issuer_key
        )

        if issuer is None:
            issuer = self.issuer

        if subject is None:
            subject = self.subject

        if validity is None:
            validity = self.validity

        if spki is None:
            spki = key.public_key().export_key(
                format="DER"
            )

        if outer_algorithm is None:
            outer_algorithm = inner_algorithm

        tbs = _wire(
            0x30,
            version
            + serial
            + inner_algorithm
            + issuer
            + validity
            + subject
            + spki
            + optional,
        )

        signature = pkcs1_15.new(
            issuer_key
        ).sign(
            hashmod.new(tbs)
        )

        if signature_value is None:
            signature_value = _wire(
                0x03,
                b"\x00" + signature,
            )

        cert = _wire(
            0x30,
            tbs
            + outer_algorithm
            + signature_value,
        )

        return cert, tbs, issuer, signature

    def parse_fixture(self, **kwargs):
        cert, _, _, _ = self.fixture(**kwargs)
        return parse_certificate(cert)

    def assert_invalid_fixture(self, **kwargs):
        cert, _, _, _ = self.fixture(**kwargs)

        with self.assertRaises(InvalidSignatureError):
            parse_certificate(cert)

    def test_parse_medimo_certificate(self):
        result = parse_certificate(
            self.medimo_cert
        )

        self.assertEqual(
            result["subject_cn"],
            "alice_01",
        )

        self.assertEqual(
            result["not_before"],
            self.start,
        )

        self.assertEqual(
            result["not_after"],
            self.end,
        )

        self.assertTrue(
            result["serial"] > 0
        )

    def test_return_dictionary_types(self):
        result = self.parse_fixture()

        expected = {
            "tbs_der": bytes,
            "signature": bytes,
            "public_key_pem": bytes,
            "subject_cn": str,
            "serial": int,
            "issuer_der": bytes,
            "not_before": datetime,
            "not_after": datetime,
        }

        self.assertEqual(
            set(result),
            set(expected),
        )

        for name, expected_type in expected.items():
            with self.subTest(name=name):
                self.assertIs(
                    type(result[name]),
                    expected_type,
                )

    def test_raw_tbs_preservation(self):
        cert, tbs, _, signature = self.fixture()

        result = parse_certificate(cert)

        self.assertEqual(
            result["tbs_der"],
            tbs,
        )

        self.assertEqual(
            result["signature"],
            signature,
        )

        self.assertTrue(
            tbs in cert
        )

    def test_raw_issuer_preservation(self):
        attributes = sorted([
            _attribute(
                _CN_OID,
                0x13,
                b"External CA",
            ),
            _attribute(
                _ORG_OID,
                0x0c,
                "Organisation É".encode("utf-8"),
            ),
        ])

        issuer = _wire(
            0x30,
            _wire(
                0x31,
                b"".join(attributes),
            ),
        )

        cert, _, original, _ = self.fixture(
            issuer=issuer
        )

        result = parse_certificate(cert)

        self.assertEqual(
            result["issuer_der"],
            original,
        )

        self.assertEqual(
            result["issuer_der"],
            issuer,
        )

    def test_public_key_extraction(self):
        result = self.parse_fixture()

        expected = self.key3072.public_key()

        actual = RSA.import_key(
            result["public_key_pem"]
        )

        self.assertFalse(
            actual.has_private()
        )

        self.assertEqual(
            (actual.n, actual.e),
            (expected.n, expected.e),
        )

        self.assertEqual(
            result["public_key_pem"],
            expected.export_key(format="PEM"),
        )

    def test_cn_and_serial(self):
        result = self.parse_fixture(
            subject=_name("é_用户"),
            serial=bytes.fromhex("02020080"),
        )

        self.assertEqual(
            result["subject_cn"],
            "é_用户",
        )

        self.assertEqual(
            result["serial"],
            128,
        )

    def test_timezone_aware_validity(self):
        result = self.parse_fixture()

        for field in ("not_before", "not_after"):
            value = result[field]

            self.assertIsNotNone(value.tzinfo)

            self.assertEqual(
                value.utcoffset(),
                timedelta(0),
            )

            self.assertEqual(
                value.microsecond,
                0,
            )

    def test_utc_year_boundaries(self):
        cases = [
            (
                b"500101000000Z",
                b"510101000000Z",
                1950,
                1951,
            ),
            (
                b"680101000000Z",
                b"690101000000Z",
                1968,
                1969,
            ),
            (
                b"990101000000Z",
                b"000101000000Z",
                1999,
                2000,
            ),
            (
                b"480101000000Z",
                b"490101000000Z",
                2048,
                2049,
            ),
        ]

        for before, after, y1, y2 in cases:
            with self.subTest(year=y1):
                result = self.parse_fixture(
                    validity=_validity(
                        _wire(0x17, before),
                        _wire(0x17, after),
                    ),
                )

                self.assertEqual(
                    result["not_before"].year,
                    y1,
                )

                self.assertEqual(
                    result["not_after"].year,
                    y2,
                )

    def test_generalized_time_external(self):
        result = self.parse_fixture(
            validity=_validity(
                b"\x17\x0d491231235959Z",
                b"\x18\x0f20510101000000Z",
            ),
        )

        self.assertEqual(
            result["not_before"],
            datetime(
                2049, 12, 31, 23, 59, 59,
                tzinfo=timezone.utc,
            ),
        )

        self.assertEqual(
            result["not_after"],
            datetime(
                2051, 1, 1,
                tzinfo=timezone.utc,
            ),
        )

        result = self.parse_fixture(
            validity=_validity(
                b"\x18\x0f20500101000000Z",
                b"\x18\x0f20520101000000Z",
            ),
        )

        self.assertEqual(
            result["not_before"].year,
            2050,
        )

        self.assertEqual(
            result["not_after"].year,
            2052,
        )

    def test_external_ca_signature(self):
        cert, tbs, issuer, signature = self.fixture()

        result = parse_certificate(cert)

        self.assertEqual(
            result["issuer_der"],
            issuer,
        )

        self.assertNotEqual(
            self.issuer,
            self.subject,
        )

        self.assertEqual(len(signature), 256)

        subject_key = RSA.import_key(
            result["public_key_pem"]
        )

        self.assertEqual(
            subject_key.size_in_bits(),
            3072,
        )

        pkcs1_15.new(
            self.key2048.public_key()
        ).verify(
            SHA256.new(tbs),
            signature,
        )

        self.assertFalse(
            rsa_verify(
                result["public_key_pem"],
                tbs,
                signature,
            )
        )

    def test_external_validity_duration(self):
        result = self.parse_fixture()

        self.assertEqual(
            result["not_after"] - result["not_before"],
            timedelta(days=365),
        )

        self.assertNotEqual(
            result["not_after"] - result["not_before"],
            timedelta(days=730),
        )

    def test_malformed_outer_structure(self):
        cert, tbs, _, signature = self.fixture()

        cases = [
            b"\x30\x00",
            _wire(0x04, cert),
            _wire(0x30, tbs + _SIG_NULL),
            _wire(
                0x30,
                parse_der(cert).value + b"\x05\x00",
            ),
            _wire(
                0x30,
                b"\x30\x00"
                + _SIG_NULL
                + _wire(0x03, b"\x00" + signature),
            ),
        ]

        for value in cases:
            with self.subTest(length=len(value)):
                with self.assertRaises(InvalidSignatureError):
                    parse_certificate(value)

    def test_truncation_and_trailing(self):
        cert, _, _, _ = self.fixture()

        cases = (
            b"",
            cert[:1],
            cert[:2],
            cert[:4],
            cert[:-1],
            cert + b"\x00",
            cert + b"\x05\x00",
        )

        for value in cases:
            with self.subTest(length=len(value)):
                with self.assertRaises(InvalidSignatureError):
                    parse_certificate(value)

    def test_invalid_serials(self):
        cases = (
            b"\x02\x01\x00",
            b"\x02\x01\xff",
            b"\x02\x02\x00\x01",
            b"\x02\x00",
            b"\x04\x01\x01",
            b"\x02\x15\x01" + b"\x00" * 20,
        )

        for serial in cases:
            with self.subTest(serial=serial.hex()):
                self.assert_invalid_fixture(
                    serial=serial
                )

        result = self.parse_fixture(
            serial=_positive_integer(
                (1 << 159) - 1
            ),
        )

        self.assertEqual(
            result["serial"],
            (1 << 159) - 1,
        )

    def test_signature_algorithm_mismatch(self):
        cases = [
            (_SIG_NULL, _SIG_SHA384),
            (_SIG_SHA384, _SIG_NULL),
            (_SIG_NULL, _SIG_ABSENT),
            (_SIG_ABSENT, _SIG_NULL),
        ]

        for inner, outer in cases:
            with self.subTest(
                inner=inner.hex(),
                outer=outer.hex(),
            ):
                self.assert_invalid_fixture(
                    inner_algorithm=inner,
                    outer_algorithm=outer,
                )

    def test_malformed_algorithm_parameters(self):
        oid = bytes.fromhex(
            "06092a864886f70d01010b"
        )

        cases = (
            _wire(0x30, oid + b"\x02\x01\x00"),
            _wire(0x30, oid + b"\x05\x01\x00"),
            _wire(0x30, oid + b"\x05\x00\x05\x00"),
            b"\x30\x02\x05\x00",
            b"\x30\x00",
        )

        for algorithm in cases:
            with self.subTest(
                algorithm=algorithm.hex()
            ):
                self.assert_invalid_fixture(
                    inner_algorithm=algorithm
                )

    def test_absent_algorithm_parameters(self):
        spki = _spki(
            self.key3072.n,
            self.key3072.e,
            algorithm=_RSA_ABSENT,
        )

        result = self.parse_fixture(
            inner_algorithm=_SIG_ABSENT,
            spki=spki,
        )

        imported = RSA.import_key(
            result["public_key_pem"]
        )

        self.assertEqual(
            (imported.n, imported.e),
            (self.key3072.n, self.key3072.e),
        )

    def test_unsupported_signature_algorithm(self):
        cert, _, _, _ = self.fixture(
            inner_algorithm=_SIG_SHA384,
            hashmod=SHA384,
        )

        with self.assertRaises(UnsupportedSignatureError):
            parse_certificate(cert)

    def test_malformed_spki(self):
        n = _positive_integer(
            self.key3072.n
        )

        e = _positive_integer(
            self.key3072.e
        )

        valid_rsa = _wire(
            0x30,
            n + e,
        )

        invalid_algorithm = _wire(
            0x30,
            bytes.fromhex(
                "06092a864886f70d010101"
            )
            + b"\x02\x01\x00",
        )

        cases = [
            b"\x30\x00",
            _wire(
                0x30,
                _RSA_NULL + b"\x03\x01\x00",
            ),
            _wire(
                0x30,
                _RSA_NULL
                + _wire(
                    0x03,
                    b"\x00" + valid_rsa + b"\x00",
                ),
            ),
            _wire(
                0x30,
                _RSA_NULL
                + _wire(
                    0x03,
                    b"\x00"
                    + _wire(
                        0x30,
                        n + e + b"\x02\x01\x01",
                    ),
                ),
            ),
            _wire(
                0x30,
                invalid_algorithm
                + _wire(
                    0x03,
                    b"\x00" + valid_rsa,
                ),
            ),
            _wire(
                0x30,
                _RSA_NULL + b"\x03\x02\x01\x80",
            ),
            _wire(
                0x30,
                _RSA_NULL
                + _wire(
                    0x03,
                    b"\x00" + b"\x30\x03\x02\x02\x01",
                ),
            ),
        ]

        for spki in cases:
            with self.subTest(length=len(spki)):
                self.assert_invalid_fixture(
                    spki=spki
                )

    def test_non_rsa_public_key(self):
        key = ECC.generate(
            curve="P-256"
        )

        spki = key.public_key().export_key(
            format="DER"
        )

        cert, _, _, _ = self.fixture(
            spki=spki
        )

        with self.assertRaises(UnsupportedSignatureError):
            parse_certificate(cert)

    def test_supported_rsa_sizes(self):
        for key in (
            self.key2048,
            self.key3072,
            self.key4096,
        ):
            with self.subTest(
                bits=key.size_in_bits()
            ):
                result = self.parse_fixture(
                    key=key
                )

                imported = RSA.import_key(
                    result["public_key_pem"]
                )

                self.assertEqual(
                    imported.size_in_bits(),
                    key.size_in_bits(),
                )

                self.assertEqual(
                    (imported.n, imported.e),
                    (key.n, key.e),
                )

    def test_unsupported_rsa_sizes(self):
        small = RSA.generate(1024)

        cert, _, _, _ = self.fixture(
            key=small
        )

        with self.assertRaises(UnsupportedSignatureError):
            parse_certificate(cert)

        oversized_spki = _spki(
            (1 << 4096) | 1,
            65537,
        )

        cert, _, _, _ = self.fixture(
            spki=oversized_spki
        )

        with self.assertRaises(UnsupportedSignatureError):
            parse_certificate(cert)

    def test_invalid_public_exponents(self):
        n = self.key3072.n

        values = (
            0,
            1,
            2,
            4,
            65536,
            n,
            n + 2,
        )

        for e in values:
            with self.subTest(exponent=e):
                self.assert_invalid_fixture(
                    spki=_spki(n, e)
                )

        self.assert_invalid_fixture(
            spki=_spki(
                n,
                self.key3072.p,
            )
        )

    def test_invalid_moduli(self):
        for n in (
            0,
            self.key3072.n - 1,
        ):
            with self.subTest(modulus=n):
                self.assert_invalid_fixture(
                    spki=_spki(n, 65537)
                )

        negative_modulus = _wire(
            0x30,
            b"\x02\x01\xff"
            + _positive_integer(65537),
        )

        spki = _wire(
            0x30,
            _RSA_NULL
            + _wire(
                0x03,
                b"\x00" + negative_modulus,
            ),
        )

        self.assert_invalid_fixture(
            spki=spki
        )

    def test_invalid_signature_bit_string(self):
        cases = (
            b"\x03\x01\x00",
            b"\x03\x02\x01\x80",
            b"\x03\x02\x07\x81",
            b"\x03\x02\x08\x00",
            b"\x03\x00",
            b"\x04\x01\x00",
        )

        for signature_value in cases:
            with self.subTest(
                value=signature_value.hex()
            ):
                self.assert_invalid_fixture(
                    signature_value=signature_value
                )

    def test_malformed_validity(self):
        good_before = b"\x17\x0d260101000000Z"
        good_after = b"\x17\x0d270101000000Z"

        cases = [
            b"\x30\x00",
            _wire(0x30, good_before),
            _wire(
                0x30,
                good_before
                + good_after
                + good_after,
            ),
            _validity(
                good_after,
                good_before,
            ),
            _validity(
                _wire(0x17, b"260230000000Z"),
                good_after,
            ),
            _validity(
                _wire(0x17, b"2601010000Z"),
                good_after,
            ),
            _validity(
                _wire(0x17, b"260101000000+0700"),
                good_after,
            ),
            _validity(
                _wire(
                    0x18,
                    b"20260101000000.5Z",
                ),
                good_after,
            ),
            _validity(
                _wire(0x0c, b"260101000000Z"),
                good_after,
            ),
        ]

        for validity in cases:
            with self.subTest(
                validity=validity.hex()
            ):
                self.assert_invalid_fixture(
                    validity=validity
                )

    def test_supported_versions_and_optional_fields(self):
        unique_ids = bytes.fromhex(
            "810200aa820200bb"
        )

        cases = (
            (b"", b""),
            (
                bytes.fromhex("a003020101"),
                unique_ids,
            ),
            (
                _VERSION_3,
                unique_ids
                + _extensions(
                    self.basic_constraints,
                    self.key_usage,
                ),
            ),
        )

        for version, optional in cases:
            with self.subTest(
                version=version.hex()
            ):
                result = self.parse_fixture(
                    version=version,
                    optional=optional,
                )

                self.assertEqual(
                    result["subject_cn"],
                    "external_user",
                )

    def test_invalid_versions_and_optional_fields(self):
        extensions = _extensions(
            self.basic_constraints
        )

        uid1 = bytes.fromhex("810200aa")
        uid2 = bytes.fromhex("820200bb")

        cases = (
            (
                bytes.fromhex("a003020100"),
                b"",
            ),
            (
                bytes.fromhex("a003020103"),
                b"",
            ),
            (
                bytes.fromhex("a006020102020102"),
                b"",
            ),
            (b"", uid1),
            (b"", extensions),
            (
                bytes.fromhex("a003020101"),
                extensions,
            ),
            (_VERSION_3, uid1 + uid1),
            (_VERSION_3, uid2 + uid1),
            (_VERSION_3, extensions + uid1),
            (_VERSION_3, extensions + extensions),
            (_VERSION_3, b"\x84\x00"),
            (_VERSION_3, b"\x81\x01\x00"),
            (_VERSION_3, b"\xa1\x03\x02\x01\x01"),
        )

        for version, optional in cases:
            with self.subTest(
                version=version.hex(),
                optional=optional.hex(),
            ):
                self.assert_invalid_fixture(
                    version=version,
                    optional=optional,
                )

    def test_malformed_names(self):
        first = _attribute(
            _CN_OID,
            0x0c,
            b"alice",
        )

        second = _attribute(
            _ORG_OID,
            0x0c,
            b"Example",
        )

        descending = b"".join(
            sorted(
                [first, second],
                reverse=True,
            )
        )

        cases = (
            b"\x30\x02\x31\x00",
            _wire(
                0x30,
                _wire(0x31, b"\x30\x00"),
            ),
            _name(b"\xff", tag=0x0c),
            _name(b"user_name", tag=0x13),
            _name(b"alice", tag=0x16),
            _name(b"", tag=0x0c),
            _name(b"a" * 65, tag=0x0c),
            _name(b"\xd8\x00", tag=0x1e),
            _wire(
                0x30,
                _wire(0x31, descending),
            ),
        )

        for subject in cases:
            with self.subTest(
                subject=subject.hex()
            ):
                self.assert_invalid_fixture(
                    subject=subject
                )

        self.assert_invalid_fixture(
            issuer=b"\x30\x00"
        )

    def test_external_cn_encodings(self):
        cases = (
            (
                _name(b"Alice Example", tag=0x13),
                "Alice Example",
            ),
            (
                _name("Alice_é"),
                "Alice_é",
            ),
            (
                _name(
                    "用户".encode("utf-16-be"),
                    tag=0x1e,
                ),
                "用户",
            ),
            (
                _name(
                    "用户".encode("utf-32-be"),
                    tag=0x1c,
                ),
                "用户",
            ),
        )

        for subject, expected in cases:
            with self.subTest(expected=expected):
                result = self.parse_fixture(
                    subject=subject
                )

                self.assertEqual(
                    result["subject_cn"],
                    expected,
                )

    def test_missing_or_ambiguous_subject_cn(self):
        no_cn = _wire(
            0x30,
            _wire(
                0x31,
                _attribute(
                    _ORG_OID,
                    0x0c,
                    b"Organization",
                ),
            ),
        )

        duplicate_cn = _wire(
            0x30,
            _wire(
                0x31,
                _attribute(
                    _CN_OID,
                    0x0c,
                    b"Alice",
                ),
            )
            + _wire(
                0x31,
                _attribute(
                    _CN_OID,
                    0x0c,
                    b"Bob",
                ),
            ),
        )

        cases = (
            no_cn,
            duplicate_cn,
            _name(b"Alice", tag=0x14),
        )

        for subject in cases:
            with self.subTest(
                subject=subject.hex()
            ):
                cert, _, _, _ = self.fixture(
                    subject=subject
                )

                with self.assertRaises(
                    UnsupportedSignatureError
                ):
                    parse_certificate(cert)

    def test_malformed_extensions(self):
        explicit_false_critical = _wire(
            0x30,
            _BC_OID
            + b"\x01\x01\x00"
            + b"\x04\x02\x30\x00",
        )

        cases = [
            _extensions(),
            _extensions(b"\x30\x00"),
            _extensions(
                explicit_false_critical
            ),
            _extensions(
                _extension(
                    _BC_OID,
                    b"\x30\x03\x01\x01\x00",
                    critical=True,
                ),
            ),
            _extensions(
                _extension(
                    _BC_OID,
                    b"\x30\x03\x02\x01\x01",
                ),
            ),
            _extensions(
                _extension(
                    _BC_OID,
                    b"\x30\x06\x01\x01\xff\x02\x01\xff",
                ),
            ),
            _extensions(
                _extension(
                    _BC_OID,
                    b"\x30\x00\x00",
                ),
            ),
            _extensions(
                _extension(
                    _BC_OID,
                    b"\x30\x03\x02\x02\x01",
                ),
            ),
            _extensions(
                _extension(
                    _KU_OID,
                    b"\x03\x02\x00\xc0",
                ),
            ),
            _extensions(
                _extension(
                    _KU_OID,
                    b"\x03\x02\x06\xc1",
                ),
            ),
            _extensions(
                _extension(
                    _KU_OID,
                    b"\x03\x01\x00",
                ),
            ),
            _extensions(
                _extension(
                    _KU_OID,
                    b"\x03\x03\x06\x00\x40",
                ),
            ),
            _extensions(
                _extension(
                    _UNKNOWN_OID,
                    b"\x30\x03\x02\x02\x01",
                ),
            ),
            bytes.fromhex("a30430003000"),
        ]

        for optional in cases:
            with self.subTest(
                optional=optional.hex()
            ):
                self.assert_invalid_fixture(
                    optional=optional
                )

    def test_duplicate_extensions(self):
        unknown = _extension(
            _UNKNOWN_OID,
            b"\x05\x00",
        )

        cases = (
            _extensions(
                self.basic_constraints,
                self.basic_constraints,
            ),
            _extensions(
                self.key_usage,
                self.key_usage,
            ),
            _extensions(
                unknown,
                unknown,
            ),
        )

        for optional in cases:
            with self.subTest(
                optional=optional.hex()
            ):
                self.assert_invalid_fixture(
                    optional=optional
                )

    def test_external_extensions(self):
        ca_basic_constraints = _extension(
            _BC_OID,
            bytes.fromhex(
                "30060101ff020101"
            ),
            critical=True,
        )

        ca_key_usage = _extension(
            _KU_OID,
            bytes.fromhex("03020204"),
            critical=True,
        )

        unknown_noncritical = _extension(
            _UNKNOWN_OID,
            b"\x05\x00",
        )

        result = self.parse_fixture(
            optional=_extensions(
                ca_basic_constraints,
                ca_key_usage,
                unknown_noncritical,
            ),
        )

        self.assertEqual(
            result["subject_cn"],
            "external_user",
        )

        unknown_critical = _extension(
            _UNKNOWN_OID,
            b"\x05\x00",
            critical=True,
        )

        cert, _, _, _ = self.fixture(
            optional=_extensions(
                unknown_critical
            ),
        )

        with self.assertRaises(UnsupportedSignatureError):
            parse_certificate(cert)

    def test_der_error_mapping(self):
        cases = (
            (
                b"\x30\x03\x02\x02\x01",
                "malformed",
                "structural",
            ),
            (
                b"\x30\x80\x00\x00",
                "non_der",
                "canonical",
            ),
            (
                b"\x30\x81\x00",
                "non_der",
                "canonical",
            ),
            (
                b"\x00" * (MAX_INPUT_SIZE + 1),
                "malformed",
                "resource_limit",
            ),
        )

        for data, kind, reason in cases:
            with self.subTest(
                kind=kind,
                reason=reason,
            ):
                with self.assertRaises(
                    InvalidSignatureError
                ) as caught:
                    parse_certificate(data)

                cause = caught.exception.__cause__

                self.assertIsInstance(
                    cause,
                    DerError,
                )

                self.assertEqual(
                    cause.kind,
                    kind,
                )

                self.assertEqual(
                    cause.reason,
                    reason,
                )

    def test_invalid_input_types(self):
        values = (
            None,
            123,
            True,
            "certificate",
            bytearray(b"\x30\x00"),
            memoryview(b"\x30\x00"),
        )

        for value in values:
            with self.subTest(
                input_type=type(value).__name__
            ):
                with self.assertRaises(
                    InvalidSignatureError
                ):
                    parse_certificate(value)

    # ========================================================
    # Stage 4c: Additional defensive test helpers
    # ========================================================

    def rewrite_medimo_certificate(
        self,
        *,
        replacements=None,
        signature=None,
    ):
        """Modify certificate fields without signing the new TBS."""

        tbs, algorithm, signature_element = decode_value(
            parse_der(self.medimo_cert),
            0x30,
        )

        fields = [
            element.raw
            for element in decode_value(tbs, 0x30)
        ]

        for index, raw in (replacements or {}).items():
            fields[index] = raw

        modified_tbs = _wire(
            0x30,
            b"".join(fields),
        )

        if signature is None:
            signature_value = signature_element.raw
        else:
            signature_value = _wire(
                0x03,
                b"\x00" + signature,
            )

        modified_certificate = _wire(
            0x30,
            modified_tbs
            + algorithm.raw
            + signature_value,
        )

        return modified_certificate, modified_tbs

    def assert_resource_rejection(self, cert):
        with self.assertRaises(
            InvalidSignatureError
        ) as caught:
            parse_certificate(cert)

        cause = caught.exception.__cause__

        self.assertIsInstance(cause, DerError)
        self.assertEqual(cause.kind, "malformed")
        self.assertEqual(cause.reason, "resource_limit")

    def fixture_with_extension_payload(self, payload):
        cert, _, _, _ = self.fixture(
            optional=_extensions(
                _extension(
                    _UNKNOWN_OID,
                    payload,
                ),
            ),
        )

        return cert

    def openssl_verify_signature(
        self,
        public_key_pem,
        tbs_der,
        signature,
    ):
        """Verify raw TBS bytes independently using OpenSSL."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            key_path = root / "public.pem"
            signature_path = root / "signature.bin"

            key_path.write_bytes(public_key_pem)
            signature_path.write_bytes(signature)

            return subprocess.run(
                [
                    "openssl",
                    "dgst",
                    "-sha256",
                    "-verify",
                    str(key_path),
                    "-signature",
                    str(signature_path),
                ],
                input=tbs_der,
                capture_output=True,
                timeout=15,
                check=False,
            )

    # ========================================================
    # Stage 4c: Additional defensive security tests
    # ========================================================

    def test_build_parse_verify_round_trip(self):
        result = parse_certificate(
            self.medimo_cert
        )

        outer = decode_value(
            parse_der(self.medimo_cert),
            0x30,
        )

        fields = decode_value(
            outer[0],
            0x30,
        )

        self.assertEqual(
            result["tbs_der"],
            outer[0].raw,
        )

        self.assertEqual(
            result["issuer_der"],
            fields[3].raw,
        )

        self.assertEqual(
            result["subject_cn"],
            "alice_01",
        )

        self.assertEqual(
            result["serial"],
            decode_value(fields[1], 0x02),
        )

        self.assertTrue(
            rsa_verify(
                result["public_key_pem"],
                result["tbs_der"],
                result["signature"],
            )
        )

    def test_parsed_certificate_signature_independent_reference(self):
        result = parse_certificate(
            self.medimo_cert
        )

        public_key = RSA.import_key(
            result["public_key_pem"]
        )

        digest = SHA256.new(
            result["tbs_der"]
        )

        pkcs1_15.new(public_key).verify(
            digest,
            result["signature"],
        )

        expected_signature = pkcs1_15.new(
            self.key3072
        ).sign(digest)

        self.assertEqual(
            result["signature"],
            expected_signature,
        )

    def test_modified_tbs_certificate(self):
        original = parse_certificate(
            self.medimo_cert
        )

        new_serial = (
            1 if original["serial"] != 1 else 2
        )

        new_validity = _validity(
            b"\x17\x0d260101000000Z",
            b"\x17\x0d290101000000Z",
        )

        cases = (
            {1: _positive_integer(new_serial)},
            {4: new_validity},
        )

        for replacements in cases:
            with self.subTest(
                fields=tuple(replacements)
            ):
                cert, modified_tbs = (
                    self.rewrite_medimo_certificate(
                        replacements=replacements
                    )
                )

                parsed = parse_certificate(cert)

                self.assertNotEqual(
                    parsed["tbs_der"],
                    original["tbs_der"],
                )

                self.assertEqual(
                    parsed["tbs_der"],
                    modified_tbs,
                )

                self.assertEqual(
                    parsed["issuer_der"],
                    original["issuer_der"],
                )

                self.assertEqual(
                    parsed["signature"],
                    original["signature"],
                )

                self.assertEqual(
                    parsed["public_key_pem"],
                    original["public_key_pem"],
                )

                self.assertFalse(
                    rsa_verify(
                        parsed["public_key_pem"],
                        parsed["tbs_der"],
                        parsed["signature"],
                    )
                )

    def test_modified_certificate_signature(self):
        original = parse_certificate(
            self.medimo_cert
        )

        signature = original["signature"]

        modified_signature = (
            signature[:-1]
            + bytes([signature[-1] ^ 1])
        )

        cert, modified_tbs = (
            self.rewrite_medimo_certificate(
                signature=modified_signature,
            )
        )

        parsed = parse_certificate(cert)

        self.assertEqual(
            modified_tbs,
            original["tbs_der"],
        )

        self.assertEqual(
            parsed["signature"],
            modified_signature,
        )

        self.assertEqual(
            parsed["tbs_der"],
            original["tbs_der"],
        )

        self.assertFalse(
            rsa_verify(
                parsed["public_key_pem"],
                parsed["tbs_der"],
                parsed["signature"],
            )
        )

    def test_certificate_public_key_substitution(self):
        original = parse_certificate(
            self.medimo_cert
        )

        substitute = self.key4096.public_key()

        cert, modified_tbs = (
            self.rewrite_medimo_certificate(
                replacements={
                    6: substitute.export_key(format="DER"),
                },
            )
        )

        parsed = parse_certificate(cert)

        imported = RSA.import_key(
            parsed["public_key_pem"]
        )

        self.assertEqual(
            (imported.n, imported.e),
            (substitute.n, substitute.e),
        )

        self.assertNotEqual(
            parsed["public_key_pem"],
            original["public_key_pem"],
        )

        self.assertEqual(
            parsed["signature"],
            original["signature"],
        )

        self.assertEqual(
            parsed["tbs_der"],
            modified_tbs,
        )

        self.assertFalse(
            rsa_verify(
                parsed["public_key_pem"],
                parsed["tbs_der"],
                parsed["signature"],
            )
        )

        # The original public key must also reject
        # the modified TBS with the original signature.
        self.assertFalse(
            rsa_verify(
                original["public_key_pem"],
                parsed["tbs_der"],
                parsed["signature"],
            )
        )

    def test_certificate_key_matches_original_private_key(self):
        parsed = parse_certificate(
            self.medimo_cert
        )

        certificate_key = RSA.import_key(
            parsed["public_key_pem"]
        )

        expected = self.key3072.public_key()

        self.assertFalse(
            certificate_key.has_private()
        )

        self.assertEqual(
            (certificate_key.n, certificate_key.e),
            (self.key3072.n, self.key3072.e),
        )

        self.assertEqual(
            certificate_key.export_key(format="DER"),
            expected.export_key(format="DER"),
        )

        self.assertEqual(
            SHA256.new(
                certificate_key.export_key(format="DER")
            ).digest(),
            SHA256.new(
                expected.export_key(format="DER")
            ).digest(),
        )

    def test_certificate_and_document_signature_substitution(self):
        parsed = parse_certificate(
            self.medimo_cert
        )

        document = b"Medimo dummy document signature input"

        self.assertNotEqual(
            document,
            parsed["tbs_der"],
        )

        document_signature = rsa_sign(
            self.key3072,
            document,
        )

        pem = parsed["public_key_pem"]

        self.assertTrue(
            rsa_verify(
                pem,
                document,
                document_signature,
            )
        )

        self.assertTrue(
            rsa_verify(
                pem,
                parsed["tbs_der"],
                parsed["signature"],
            )
        )

        self.assertFalse(
            rsa_verify(
                pem,
                document,
                parsed["signature"],
            )
        )

        self.assertFalse(
            rsa_verify(
                pem,
                parsed["tbs_der"],
                document_signature,
            )
        )

    def test_malformed_nested_extension_payloads(self):
        cases = (
            # Nested child exceeds its parent's boundary.
            bytes.fromhex(
                "3005a003020201"
            ),

            # Non-minimal length inside nested DER.
            bytes.fromhex(
                "300404810178"
            ),

            # Constructed BOOLEAN, prohibited ASN.1 form.
            bytes.fromhex(
                "30032101ff"
            ),

            # Non-canonical TRUE inside nested DER.
            bytes.fromhex(
                "3003010101"
            ),
        )

        for payload in cases:
            with self.subTest(
                payload=payload.hex()
            ):
                cert = self.fixture_with_extension_payload(
                    payload
                )

                with self.assertRaises(
                    InvalidSignatureError
                ) as caught:
                    parse_certificate(cert)

                self.assertIsInstance(
                    caught.exception.__cause__,
                    DerError,
                )

    def test_named_bit_string_nine_bit_boundary(self):
        # keyAgreement (bit 4) and decipherOnly (bit 8).
        valid = bytes.fromhex(
            "0303070880"
        )

        result = self.parse_fixture(
            optional=_extensions(
                _extension(
                    _KU_OID,
                    valid,
                    critical=True,
                ),
            ),
        )

        self.assertEqual(
            result["subject_cn"],
            "external_user",
        )

        cases = (
            # Last named bit is zero, so encoding is not minimal.
            bytes.fromhex("0303070800"),

            # Unused padding bits are non-zero.
            bytes.fromhex("0303070881"),
        )

        for payload in cases:
            with self.subTest(
                payload=payload.hex()
            ):
                self.assert_invalid_fixture(
                    optional=_extensions(
                        _extension(
                            _KU_OID,
                            payload,
                            critical=True,
                        ),
                    ),
                )

    def test_certificate_nested_depth_boundary(self):
        def nested_payload(depth):
            value = b"\x05\x00"

            for _ in range(depth - 1):
                value = _wire(0x30, value)

            return value

        valid = self.fixture_with_extension_payload(
            nested_payload(MAX_DEPTH)
        )

        result = parse_certificate(valid)

        self.assertEqual(
            result["subject_cn"],
            "external_user",
        )

        invalid = self.fixture_with_extension_payload(
            nested_payload(MAX_DEPTH + 1)
        )

        self.assert_resource_rejection(invalid)

    def test_certificate_child_count_boundary(self):
        valid_payload = _wire(
            0x30,
            b"\x05\x00" * MAX_CHILDREN,
        )

        valid = self.fixture_with_extension_payload(
            valid_payload
        )

        result = parse_certificate(valid)

        self.assertEqual(
            result["subject_cn"],
            "external_user",
        )

        invalid_payload = _wire(
            0x30,
            b"\x05\x00" * (MAX_CHILDREN + 1),
        )

        invalid = self.fixture_with_extension_payload(
            invalid_payload
        )

        self.assert_resource_rejection(invalid)

    def test_certificate_total_elements_boundary(self):
        def make_payload(total):
            groups = 8

            # Count the root and all group sequences.
            leaves = total - 1 - groups

            count, remainder = divmod(
                leaves,
                groups,
            )

            children = []

            for index in range(groups):
                size = count + (
                    1 if index < remainder else 0
                )

                self.assertLessEqual(
                    size,
                    MAX_CHILDREN,
                )

                children.append(
                    _wire(
                        0x30,
                        b"\x05\x00" * size,
                    )
                )

            return _wire(
                0x30,
                b"".join(children),
            )

        valid = self.fixture_with_extension_payload(
            make_payload(MAX_TOTAL_ELEMENTS)
        )

        result = parse_certificate(valid)

        self.assertEqual(
            result["subject_cn"],
            "external_user",
        )

        invalid = self.fixture_with_extension_payload(
            make_payload(MAX_TOTAL_ELEMENTS + 1)
        )

        self.assert_resource_rejection(invalid)

    def test_certificate_element_length_boundary(self):
        _, base_tbs, _, signature = self.fixture()

        base_content = parse_der(
            base_tbs
        ).value

        signature_value = _wire(
            0x03,
            b"\x00" + signature,
        )

        def certificate_at_length(target):
            payload_length = target - 2000

            for _ in range(10):
                optional = _extensions(
                    _extension(
                        _UNKNOWN_OID,
                        _wire(
                            0x04,
                            b"x" * payload_length,
                        ),
                    ),
                )

                tbs = _wire(
                    0x30,
                    base_content + optional,
                )

                actual = (
                    len(tbs)
                    + len(_SIG_NULL)
                    + len(signature_value)
                )

                if actual == target:
                    cert, actual_tbs, _, _ = self.fixture(
                        optional=optional
                    )

                    self.assertEqual(
                        actual_tbs,
                        tbs,
                    )

                    return cert

                payload_length += target - actual

            self.fail(
                "Unable to construct exact boundary fixture"
            )

        valid = certificate_at_length(
            MAX_ELEMENT_LENGTH
        )

        self.assertEqual(
            parse_der(valid).length,
            MAX_ELEMENT_LENGTH,
        )

        result = parse_certificate(valid)

        self.assertEqual(
            result["subject_cn"],
            "external_user",
        )

        invalid = certificate_at_length(
            MAX_ELEMENT_LENGTH + 1
        )

        self.assert_resource_rejection(invalid)

    def test_certificate_input_size_boundary(self):
        # A single certificate cannot fill MAX_INPUT_SIZE
        # because MAX_ELEMENT_LENGTH is smaller.
        # At the input limit, trailing bytes remain invalid.
        exact_limit = (
            self.medimo_cert
            + b"\x00" * (
                MAX_INPUT_SIZE - len(self.medimo_cert)
            )
        )

        self.assertEqual(
            len(exact_limit),
            MAX_INPUT_SIZE,
        )

        with self.assertRaises(
            InvalidSignatureError
        ) as caught:
            parse_certificate(exact_limit)

        cause = caught.exception.__cause__

        self.assertIsInstance(cause, DerError)
        self.assertEqual(cause.kind, "malformed")
        self.assertEqual(cause.reason, "structural")

        # One extra byte must fail the input resource limit.
        self.assert_resource_rejection(
            exact_limit + b"\x00"
        )

    def test_parsed_leap_year_validity_consistency(self):
        start = datetime(
            2028, 2, 29,
            23, 59, 59,
            tzinfo=timezone.utc,
        )

        expected_end = datetime(
            2030, 2, 28,
            23, 59, 59,
            tzinfo=timezone.utc,
        )

        cert = build_self_signed_certificate(
            self.key3072,
            "leap_year_user",
            start,
            start + timedelta(days=730),
        )

        parsed = parse_certificate(cert)

        self.assertEqual(
            parsed["not_before"],
            start,
        )

        self.assertEqual(
            parsed["not_after"],
            expected_end,
        )

        self.assertEqual(
            parsed["not_after"] - parsed["not_before"],
            timedelta(days=730),
        )

        self.assertTrue(
            rsa_verify(
                parsed["public_key_pem"],
                parsed["tbs_der"],
                parsed["signature"],
            )
        )

        outer = decode_value(
            parse_der(cert),
            0x30,
        )

        fields = decode_value(
            outer[0],
            0x30,
        )

        self.assertEqual(
            fields[4].raw,
            b"\x30\x1e"
            b"\x17\x0d280229235959Z"
            b"\x17\x0d300228235959Z",
        )

        # Contract boundary rule for a future signingTime check.
        def within_validity(value):
            return (
                parsed["not_before"]
                <= value
                <= parsed["not_after"]
            )

        self.assertTrue(within_validity(start))
        self.assertTrue(within_validity(expected_end))

        self.assertFalse(
            within_validity(
                start - timedelta(seconds=1)
            )
        )

        self.assertFalse(
            within_validity(
                expected_end + timedelta(seconds=1)
            )
        )

    @unittest.skipUnless(
        shutil.which("openssl"),
        "OpenSSL unavailable",
    )
    def test_openssl_parsed_certificate_self_signature(self):
        parsed = parse_certificate(
            self.medimo_cert
        )

        inspection = subprocess.run(
            [
                "openssl",
                "x509",
                "-inform",
                "DER",
                "-pubkey",
                "-noout",
            ],
            input=self.medimo_cert,
            capture_output=True,
            timeout=15,
            check=True,
        )

        openssl_key = RSA.import_key(
            inspection.stdout
        )

        parser_key = RSA.import_key(
            parsed["public_key_pem"]
        )

        self.assertEqual(
            (openssl_key.n, openssl_key.e),
            (parser_key.n, parser_key.e),
        )

        valid = self.openssl_verify_signature(
            inspection.stdout,
            parsed["tbs_der"],
            parsed["signature"],
        )

        self.assertEqual(
            valid.returncode,
            0,
            valid.stderr.decode(errors="replace"),
        )

        signature = parsed["signature"]

        tampered_signature = (
            signature[:-1]
            + bytes([signature[-1] ^ 1])
        )

        invalid = self.openssl_verify_signature(
            inspection.stdout,
            parsed["tbs_der"],
            tampered_signature,
        )

        self.assertNotEqual(
            invalid.returncode,
            0,
        )

    @unittest.skipUnless(
        shutil.which("openssl"),
        "OpenSSL unavailable",
    )
    def test_openssl_external_issuer_signature(self):
        cert, original_tbs, original_issuer, signature = (
            self.fixture(
                key=self.key4096,
                issuer_key=self.key2048,
            )
        )

        parsed = parse_certificate(cert)

        self.assertEqual(
            parsed["tbs_der"],
            original_tbs,
        )

        self.assertEqual(
            parsed["issuer_der"],
            original_issuer,
        )

        self.assertEqual(
            parsed["signature"],
            signature,
        )

        inspection = subprocess.run(
            [
                "openssl",
                "x509",
                "-inform",
                "DER",
                "-pubkey",
                "-noout",
            ],
            input=cert,
            capture_output=True,
            timeout=15,
            check=True,
        )

        subject_key = RSA.import_key(
            inspection.stdout
        )

        self.assertEqual(
            (subject_key.n, subject_key.e),
            (self.key4096.n, self.key4096.e),
        )

        issuer_pem = self.key2048.public_key().export_key(
            format="PEM"
        )

        valid = self.openssl_verify_signature(
            issuer_pem,
            parsed["tbs_der"],
            parsed["signature"],
        )

        self.assertEqual(
            valid.returncode,
            0,
            valid.stderr.decode(errors="replace"),
        )

        self.assertTrue(
            rsa_verify(
                issuer_pem,
                parsed["tbs_der"],
                parsed["signature"],
            )
        )

        self.assertFalse(
            rsa_verify(
                parsed["public_key_pem"],
                parsed["tbs_der"],
                parsed["signature"],
            )
        )

    def test_unsupported_der_reason_preserved(self):
        # Fractional GeneralizedTime is valid generic DER,
        # but outside the certificate validity time profile.
        validity = _validity(
            _wire(
                0x18,
                b"20500101000000.5Z",
            ),
            _wire(
                0x18,
                b"20510101000000Z",
            ),
        )

        cert, _, _, _ = self.fixture(
            validity=validity
        )

        with self.assertRaises(
            InvalidSignatureError
        ) as caught:
            parse_certificate(cert)

        cause = caught.exception.__cause__

        self.assertIsInstance(cause, DerError)
        self.assertEqual(cause.kind, "malformed")
        self.assertEqual(cause.reason, "unsupported")


if __name__ == "__main__":
    unittest.main()