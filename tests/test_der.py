import unittest
from datetime import datetime, timedelta, timezone

from der import (
    der_length,
    der_tlv,
    der_integer,
    der_boolean,
    der_bit_string,
    der_octet_string,
    der_null,
    der_oid,
    der_utf8_string,
    der_printable_string,
    der_utc_time,
    der_generalized_time,
    der_sequence,
    der_set_of,
    der_explicit,
    der_implicit,
)


class TestDerEncoder(unittest.TestCase):

    def assert_hex(self, actual, expected):
        self.assertEqual(
            actual,
            bytes.fromhex(expected),
        )

    def test_length_boundaries(self):
        cases = [
            (0, "00"),
            (1, "01"),
            (127, "7f"),
            (128, "8180"),
            (255, "81ff"),
            (256, "820100"),
            (65535, "82ffff"),
            (65536, "83010000"),
        ]

        for value, expected in cases:
            with self.subTest(value=value):
                self.assert_hex(
                    der_length(value),
                    expected,
                )

    def test_invalid_lengths(self):
        values = (
            -1,
            True,
            1.5,
            "128",
            None,
            1 << 1008,
        )

        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    der_length(value)

    def test_tlv(self):
        self.assert_hex(
            der_tlv(0x04, b"abc"),
            "0403616263",
        )

        self.assertEqual(
            der_tlv(0x04, b"x" * 128),
            b"\x04\x81\x80" + b"x" * 128,
        )

    def test_invalid_tlv(self):
        tags = (
            -1,
            256,
            True,
            0,
            0x20,
            0x1F,
            0x9F,
            "04",
        )

        for tag in tags:
            with self.subTest(tag=tag):
                with self.assertRaises(ValueError):
                    der_tlv(tag, b"")

        with self.assertRaises(ValueError):
            der_tlv(0x04, "abc")

    def test_integer_boundaries(self):
        cases = [
            (0, "020100"),
            (1, "020101"),
            (127, "02017f"),
            (128, "02020080"),
            (255, "020200ff"),
            (256, "02020100"),
            (32767, "02027fff"),
            (32768, "0203008000"),
            (-1, "0201ff"),
            (-128, "020180"),
            (-129, "0202ff7f"),
            (-256, "0202ff00"),
            (-32768, "02028000"),
            (-32769, "0203ff7fff"),
        ]

        for value, expected in cases:
            with self.subTest(value=value):
                self.assert_hex(
                    der_integer(value),
                    expected,
                )

    def test_large_integer(self):
        self.assertEqual(
            der_integer(1 << 3071),
            bytes.fromhex("028201810080")
            + b"\x00" * 383,
        )

    def test_boolean(self):
        self.assert_hex(
            der_boolean(True),
            "0101ff",
        )

        self.assert_hex(
            der_boolean(False),
            "010100",
        )

    def test_invalid_primitive_types(self):
        cases = [
            (der_integer, True),
            (der_integer, "1"),
            (der_integer, 1.0),
            (der_boolean, 1),
            (der_boolean, None),
            (der_octet_string, "abc"),
            (der_bit_string, bytearray(b"x")),
        ]

        for function, value in cases:
            with self.subTest(
                function=function.__name__,
                value=value,
            ):
                with self.assertRaises(ValueError):
                    function(value)

    def test_bit_string(self):
        self.assert_hex(
            der_bit_string(b""),
            "030100",
        )

        self.assert_hex(
            der_bit_string(b"\xaa"),
            "030200aa",
        )

        self.assert_hex(
            der_bit_string(b"\xc0", 6),
            "030206c0",
        )

        self.assert_hex(
            der_bit_string(b"\x80", 7),
            "03020780",
        )

        self.assert_hex(
            der_bit_string(b"\xc0\x00"),
            "030300c000",
        )

    def test_named_bit_string(self):
        self.assert_hex(
            der_bit_string(
                b"\xc0\x00",
                named=True,
            ),
            "030206c0",
        )

        self.assert_hex(
            der_bit_string(
                b"\x00\x00",
                named=True,
            ),
            "030100",
        )

        self.assert_hex(
            der_bit_string(
                b"\x01\x80",
                named=True,
            ),
            "0303070180",
        )

    def test_invalid_bit_string(self):
        cases = [
            (b"\xc0", -1),
            (b"\xc0", 8),
            (b"\xc0", True),
            (b"", 1),
            (b"\xc1", 6),
            (b"\x01", 7),
        ]

        for data, count in cases:
            with self.subTest(
                data=data,
                count=count,
            ):
                with self.assertRaises(ValueError):
                    der_bit_string(data, count)

        with self.assertRaises(ValueError):
            der_bit_string(b"\x80", named=1)

    def test_octet_string_and_null(self):
        self.assert_hex(
            der_octet_string(b""),
            "0400",
        )

        self.assert_hex(
            der_octet_string(b"\x00\xff"),
            "040200ff",
        )

        self.assert_hex(
            der_null(),
            "0500",
        )

    def test_oid_known_values(self):
        cases = [
            (
                "1.2.840.113549.1.1.1",
                "06092a864886f70d010101",
            ),
            (
                "1.2.840.113549.1.1.11",
                "06092a864886f70d01010b",
            ),
            (
                "2.16.840.1.101.3.4.2.1",
                "0609608648016503040201",
            ),
            (
                "1.2.840.113549.1.7.2",
                "06092a864886f70d010702",
            ),
            (
                "2.5.29.19",
                "0603551d13",
            ),
            ("0.0", "060100"),
            ("0.39", "060127"),
            ("1.39", "06014f"),
            ("2.48", "06028100"),
            ("2.999.3", "0603883703"),
            (
                "1.2.0.127.128.16383.16384",
                "060a2a007f8100ff7f818000",
            ),
        ]

        for value, expected in cases:
            with self.subTest(value=value):
                self.assert_hex(
                    der_oid(value),
                    expected,
                )

    def test_invalid_oid(self):
        values = (
            "",
            "1",
            "3.0",
            "0.40",
            "1.40",
            "1.-2",
            "1..2",
            "1.2.",
            ".1.2",
            "1.02",
            " 1.2",
            "1.٢",
            "1.2\n",
            None,
            123,
        )

        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    der_oid(value)

    def test_strings(self):
        self.assert_hex(
            der_utf8_string("Medimo"),
            "0c064d6564696d6f",
        )

        self.assert_hex(
            der_utf8_string("é_"),
            "0c03c3a95f",
        )

        self.assert_hex(
            der_utf8_string(""),
            "0c00",
        )

        self.assert_hex(
            der_printable_string("A + B"),
            "130541202b2042",
        )

        self.assert_hex(
            der_printable_string(""),
            "1300",
        )

    def test_invalid_strings(self):
        values = (
            "user_name",
            "é",
            "user@medimo",
            "a\n",
            42,
        )

        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    der_printable_string(value)

        for value in (None, 42, "\ud800"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    der_utf8_string(value)

    def test_utc_time(self):
        cases = [
            (1950, b"500101000000Z"),
            (2049, b"490101000000Z"),
        ]

        for year, expected in cases:
            value = datetime(
                year,
                1,
                1,
                tzinfo=timezone.utc,
            )

            self.assertEqual(
                der_utc_time(value),
                b"\x17\x0d" + expected,
            )

        value = datetime(
            2028,
            2,
            29,
            12,
            34,
            56,
            tzinfo=timezone.utc,
        )

        self.assertEqual(
            der_utc_time(value),
            b"\x17\x0d280229123456Z",
        )

    def test_generalized_time(self):
        value = datetime(
            2050,
            1,
            1,
            tzinfo=timezone.utc,
        )

        self.assertEqual(
            der_generalized_time(value),
            b"\x18\x0f20500101000000Z",
        )

        value = datetime(
            1,
            1,
            1,
            tzinfo=timezone.utc,
        )

        self.assertEqual(
            der_generalized_time(value),
            b"\x18\x0f00010101000000Z",
        )

    def test_invalid_time(self):
        for year in (1949, 2050):
            with self.assertRaises(ValueError):
                der_utc_time(
                    datetime(
                        year,
                        1,
                        1,
                        tzinfo=timezone.utc,
                    )
                )

        values = (
            None,
            "261128000000Z",
            datetime(2026, 1, 1),
            datetime(
                2026,
                1,
                1,
                tzinfo=timezone(timedelta(hours=7)),
            ),
            datetime(
                2026,
                1,
                1,
                microsecond=1,
                tzinfo=timezone.utc,
            ),
        )

        for function in (
            der_utc_time,
            der_generalized_time,
        ):
            for value in values:
                with self.subTest(
                    function=function.__name__,
                    value=value,
                ):
                    with self.assertRaises(ValueError):
                        function(value)

    def test_sequence(self):
        self.assert_hex(
            der_sequence(),
            "3000",
        )

        self.assert_hex(
            der_sequence(
                der_integer(2),
                der_boolean(True),
            ),
            "30060201020101ff",
        )

    def test_set_of(self):
        self.assert_hex(
            der_set_of(),
            "3100",
        )

        self.assert_hex(
            der_set_of(
                der_integer(128),
                der_integer(2),
                der_integer(1),
            ),
            "310a02010102010202020080",
        )

        self.assert_hex(
            der_set_of(
                der_integer(1),
                der_integer(-1),
            ),
            "31060201010201ff",
        )

        self.assert_hex(
            der_set_of(
                der_integer(1),
                der_integer(1),
            ),
            "3106020101020101",
        )

    def test_context_tags(self):
        self.assert_hex(
            der_explicit(0, der_integer(2)),
            "a003020102",
        )

        self.assert_hex(
            der_explicit(3, der_sequence()),
            "a3023000",
        )

        self.assert_hex(
            der_implicit(
                0,
                der_set_of(der_integer(1)),
            ),
            "a003020101",
        )

        self.assert_hex(
            der_implicit(
                2,
                der_octet_string(b"x"),
            ),
            "820178",
        )

        self.assert_hex(
            der_explicit(30, der_null()),
            "be020500",
        )

        self.assertEqual(
            der_implicit(
                0,
                der_octet_string(b"x" * 128),
            ),
            b"\x80\x81\x80" + b"x" * 128,
        )

    def test_invalid_constructed_inputs(self):
        for function in (
            der_sequence,
            der_set_of,
        ):
            for value in (
                b"",
                b"\x02",
                "020101",
            ):
                with self.subTest(
                    function=function.__name__,
                    value=value,
                ):
                    with self.assertRaises(ValueError):
                        function(value)

        for function in (
            der_explicit,
            der_implicit,
        ):
            for number in (-1, 31, True, "0"):
                with self.subTest(
                    function=function.__name__,
                    number=number,
                ):
                    with self.assertRaises(ValueError):
                        function(
                            number,
                            der_null(),
                        )

            with self.assertRaises(ValueError):
                function(0, b"")


if __name__ == "__main__":
    unittest.main()