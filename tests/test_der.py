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


# --- DER decoder tests ---
from der import (
    DerElement, DerError, read_tlv, parse_der, decode_children,
    decode_value, decode_explicit, decode_implicit,
)


class TestDerDecoder(unittest.TestCase):
    def assert_error(self, kind, function, *args):
        with self.assertRaises(DerError) as caught:
            function(*args)
        self.assertEqual(caught.exception.kind, kind)

    def test_known_tlv_and_raw_bytes(self):
        raw = bytes.fromhex("02020080")
        element = parse_der(raw)
        self.assertIsInstance(element, DerElement)
        self.assertEqual(element.tag, 0x02)
        self.assertEqual(element.identifier, b"\x02")
        self.assertEqual(element.tag_class, 0)
        self.assertEqual(element.tag_number, 2)
        self.assertFalse(element.constructed)
        self.assertEqual(element.length, 2)
        self.assertEqual(element.value, b"\x00\x80")
        self.assertEqual(element.raw, raw)
        self.assertEqual((element.start, element.value_start, element.end), (0, 2, 4))

    def test_read_tlv_cursor(self):
        data = bytes.fromhex("0500020101")
        first, offset = read_tlv(data)
        second, end = read_tlv(data, offset)
        self.assertEqual(first.raw, bytes.fromhex("0500"))
        self.assertEqual(second.raw, bytes.fromhex("020101"))
        self.assertEqual((offset, end), (2, 5))
        self.assertEqual(second.start, 2)

    def test_length_boundaries(self):
        for size, header in ((0, "0400"), (127, "047f"), (128, "048180"),
                             (255, "0481ff"), (256, "04820100")):
            with self.subTest(size=size):
                raw = bytes.fromhex(header) + b"x" * size
                element = parse_der(raw)
                self.assertEqual(element.length, size)
                self.assertEqual(element.raw, raw)
                self.assertEqual(decode_value(element), b"x" * size)

    def test_known_integer_values(self):
        for raw, value in (("020100", 0), ("02017f", 127), ("02020080", 128),
                           ("02020100", 256), ("0201ff", -1), ("020180", -128),
                           ("0202ff7f", -129)):
            with self.subTest(raw=raw):
                self.assertEqual(decode_value(parse_der(bytes.fromhex(raw)), 0x02), value)

    def test_known_boolean_null_octets(self):
        self.assertIs(decode_value(parse_der(bytes.fromhex("0101ff"))), True)
        self.assertIs(decode_value(parse_der(bytes.fromhex("010100"))), False)
        self.assertIsNone(decode_value(parse_der(bytes.fromhex("0500"))))
        self.assertEqual(decode_value(parse_der(bytes.fromhex("040200ff"))), b"\x00\xff")

    def test_known_bit_strings(self):
        self.assertEqual(decode_value(parse_der(bytes.fromhex("030206c0"))), (b"\xc0", 6))
        self.assertEqual(decode_value(parse_der(bytes.fromhex("030100"))), (b"", 0))
        self.assertEqual(decode_value(parse_der(bytes.fromhex("030300c000"))), (b"\xc0\x00", 0))

    def test_known_oid_values(self):
        for raw, oid in (("06092a864886f70d010101", "1.2.840.113549.1.1.1"),
                         ("0609608648016503040201", "2.16.840.1.101.3.4.2.1"),
                         ("060100", "0.0"), ("06014f", "1.39"),
                         ("06028100", "2.48"), ("0603883703", "2.999.3")):
            with self.subTest(oid=oid):
                self.assertEqual(decode_value(parse_der(bytes.fromhex(raw))), oid)

    def test_known_strings(self):
        self.assertEqual(decode_value(parse_der(bytes.fromhex("0c03c3a95f"))), "é_")
        self.assertEqual(decode_value(parse_der(bytes.fromhex("130541202b2042"))), "A + B")

    def test_known_times_and_century_boundary(self):
        for year, text in ((1950, b"500101000000Z"), (1968, b"680101000000Z"),
                           (2000, b"000101000000Z"), (2049, b"490101000000Z")):
            with self.subTest(year=year):
                self.assertEqual(decode_value(parse_der(b"\x17\x0d" + text)),
                                 datetime(year, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(decode_value(parse_der(b"\x18\x0f20500101000000Z")),
                         datetime(2050, 1, 1, tzinfo=timezone.utc))

    def test_primitive_round_trips(self):
        moment = datetime(2028, 2, 29, 12, 34, 56, tzinfo=timezone.utc)
        cases = ((der_integer(1 << 3071), 1 << 3071),
                 (der_integer(-32769), -32769), (der_boolean(False), False),
                 (der_bit_string(b"\xc0", 6), (b"\xc0", 6)),
                 (der_octet_string(b"abc"), b"abc"), (der_null(), None),
                 (der_oid("2.999.3.16384"), "2.999.3.16384"),
                 (der_utf8_string("Medimo_é"), "Medimo_é"),
                 (der_printable_string("A + B"), "A + B"),
                 (der_utc_time(moment), moment), (der_generalized_time(moment), moment))
        for raw, expected in cases:
            with self.subTest(raw=raw[:12]):
                self.assertEqual(decode_value(parse_der(raw)), expected)

    def test_nested_sequence_and_exact_child_offsets(self):
        raw = bytes.fromhex("30083003020102020101")
        outer = parse_der(raw)
        inner, sibling = decode_value(outer, 0x30)
        (integer,) = decode_children(inner)
        self.assertEqual(inner.raw, bytes.fromhex("3003020102"))
        self.assertEqual(integer.raw, bytes.fromhex("020102"))
        self.assertEqual((integer.start, integer.value_start, integer.end), (4, 6, 7))
        self.assertEqual(sibling.raw, raw[7:10])
        self.assertEqual(decode_value(integer), 2)
        self.assertEqual(decode_value(sibling), 1)
        for element in (outer, inner, integer, sibling):
            self.assertEqual(element.raw, raw[element.start:element.end])

    def test_sequence_and_set_of_round_trip(self):
        raw = der_sequence(der_set_of(der_integer(2), der_integer(1)), der_null())
        elements = decode_value(parse_der(raw))
        self.assertEqual(tuple(map(decode_value, decode_value(elements[0]))), (1, 2))
        self.assertIsNone(decode_value(elements[1]))
        self.assertEqual(decode_value(parse_der(bytes.fromhex("3000"))), ())
        self.assertEqual(decode_value(parse_der(bytes.fromhex("3100"))), ())

    def test_explicit_tag(self):
        wrapper = parse_der(bytes.fromhex("a003020102"))
        child = decode_explicit(wrapper, 0)
        self.assertEqual(child.raw, bytes.fromhex("020102"))
        self.assertEqual(decode_value(child), 2)
        self.assertEqual(wrapper.raw, bytes.fromhex("a003020102"))

    def test_implicit_primitive(self):
        element = parse_der(bytes.fromhex("820178"))
        self.assertEqual((element.tag_class, element.tag_number, element.constructed), (2, 2, False))
        self.assertEqual(decode_implicit(element, 2, 0x04), b"x")
        self.assertEqual(element.raw, bytes.fromhex("820178"))

    def test_implicit_constructed_and_signed_attrs_bytes(self):
        raw = bytes.fromhex("a006020101020102")
        element = parse_der(raw)
        children = decode_implicit(element, 0, 0x31)
        self.assertEqual(tuple(map(decode_value, children)), (1, 2))
        self.assertEqual(element.raw, raw)
        self.assertEqual(b"\x31" + element.raw[1:], bytes.fromhex("3106020101020102"))
        self.assert_error("malformed", decode_explicit, element, 0)

    def test_implicit_long_form_length_raw(self):
        raw = bytes.fromhex("808180") + b"x" * 128
        element = parse_der(raw)
        self.assertEqual(decode_implicit(element, 0, 0x04), b"x" * 128)
        self.assertEqual(element.raw, raw)

    def test_truncated_tag_length_and_value(self):
        for raw in ("", "02", "0482", "048201", "04036162", "3081030201"):
            with self.subTest(raw=raw):
                self.assert_error("malformed", parse_der, bytes.fromhex(raw))

    def test_indefinite_length(self):
        for raw in ("30800201010000", "a080", "24800000"):
            with self.subTest(raw=raw):
                self.assert_error("non_der", parse_der, bytes.fromhex(raw))
        self.assert_error("malformed", parse_der, bytes.fromhex("04800000"))

    def test_non_minimal_length(self):
        for raw in (bytes.fromhex("04810161"), bytes.fromhex("04820080") + b"x" * 128,
                    bytes.fromhex("058100")):
            with self.subTest(raw=raw[:8]):
                self.assert_error("non_der", parse_der, raw)

    def test_trailing_bytes(self):
        for raw in ("050000", "0500020101", "020101ff"):
            with self.subTest(raw=raw):
                self.assert_error("malformed", parse_der, bytes.fromhex(raw))

    def test_child_cannot_cross_parent(self):
        raw = bytes.fromhex("300730020201020101")
        outer = parse_der(raw)
        inner, sibling = decode_children(outer)
        self.assertEqual(sibling.raw, bytes.fromhex("020101"))
        self.assert_error("malformed", decode_children, inner)
        self.assert_error("malformed", decode_children, parse_der(bytes.fromhex("300102")))

    def test_nested_non_der_identified_at_correct_layer(self):
        element = parse_der(bytes.fromhex("3004a0023080"))
        (wrapper,) = decode_children(element)
        self.assertEqual(wrapper.raw, bytes.fromhex("a0023080"))
        self.assert_error("non_der", decode_children, wrapper)

    def test_invalid_identifier_and_reserved_length(self):
        for raw in ("0000", "2000", "0f00", "04ff", "9f", "9f81", "9f800000", "9f1e00"):
            with self.subTest(raw=raw):
                self.assert_error("malformed", parse_der, bytes.fromhex(raw))

    def test_unknown_tags_preserved_without_typed_interpretation(self):
        raw = bytes.fromhex("9f81000178")
        element = parse_der(raw)
        self.assertEqual(element.identifier, bytes.fromhex("9f8100"))
        self.assertEqual((element.tag_class, element.tag_number), (2, 128))
        self.assertEqual(element.raw, raw)
        self.assert_error("malformed", decode_value, element)
        unknown = parse_der(bytes.fromhex("160178"))  # IA5String not in Medimo encoder profile
        self.assertEqual(unknown.raw, bytes.fromhex("160178"))
        self.assert_error("malformed", decode_value, unknown)

    def test_basic_invalid_primitive_contents(self):
        for raw in ("0100", "010200ff", "0200", "0202007f", "0202ff80", "0300", "030108",
                    "030101", "050100", "0600", "060180", "06028000", "0c01ff", "13015f"):
            with self.subTest(raw=raw):
                self.assert_error("malformed", decode_value, parse_der(bytes.fromhex(raw)))
        for raw in ("010101", "030206c1"):
            with self.subTest(raw=raw):
                self.assert_error("non_der", decode_value, parse_der(bytes.fromhex(raw)))

    def test_invalid_calendar_and_time_profile(self):
        for raw in (b"\x17\x0d260230000000Z", b"\x17\x0d261128250000Z",
                    der_tlv(0x17, b"261128000000+2460"),
                    der_tlv(0x18, b"20500101000000.5Z")):
            self.assert_error("malformed", decode_value, parse_der(raw))
        for raw in (b"\x17\x0b2611280000Z", der_tlv(0x17, b"261128000000+0700"),
                    der_tlv(0x18, b"20500101000000.50Z"),
                    der_tlv(0x18, b"20500101000000,5Z"),
                    der_tlv(0x18, b"20500101000000")):
            self.assert_error("non_der", decode_value, parse_der(raw))

    def test_wrong_tag_and_context_shape(self):
        integer = parse_der(bytes.fromhex("020101"))
        self.assert_error("malformed", decode_value, integer, 0x04)
        self.assert_error("malformed", decode_children, integer)
        self.assert_error("malformed", decode_explicit, parse_der(bytes.fromhex("a000")), 0)
        self.assert_error("malformed", decode_explicit, parse_der(bytes.fromhex("a103020101")), 0)
        self.assert_error("malformed", decode_implicit, parse_der(bytes.fromhex("800101")), 0, 0x30)
        self.assert_error("non_der", parse_der, bytes.fromhex("2403040178"))
        for raw in ("2203020101", "1000", "1100", "2180"):
            self.assert_error("malformed", parse_der, bytes.fromhex(raw))
        self.assert_error("non_der", decode_implicit, parse_der(bytes.fromhex("a003040178")), 0, 0x04)

    def test_invalid_input_and_boundaries(self):
        for value in (None, "0500", bytearray(b"\x05\x00")):
            self.assert_error("malformed", parse_der, value)
        for offset, end in ((-1, 2), (True, 2), (0, 3), (2, 1), (0, True)):
            self.assert_error("malformed", read_tlv, b"\x05\x00", offset, end)
        self.assert_error("malformed", read_tlv, bytes.fromhex("020101"), 0, 2)


# Stage 2c: independent wire fixtures and resource boundary tests.
from der import (
    validate_tree, MAX_INPUT_SIZE, MAX_ELEMENT_LENGTH, MAX_DEPTH,
    MAX_CHILDREN, MAX_TOTAL_ELEMENTS, MAX_LENGTH_OCTETS,
    MAX_TAG_OCTETS, MAX_OID_ARCS, MAX_OID_COMPONENT_OCTETS,
    MAX_OID_SIZE,
)


class TestDerHardening(unittest.TestCase):
    def assert_failure(self, kind, reason, fn, *args, **kwargs):
        with self.assertRaises(DerError) as caught:
            fn(*args, **kwargs)
        self.assertEqual(caught.exception.kind, kind)
        self.assertEqual(caught.exception.reason, reason)

    @staticmethod
    def wire(tag, content):
        # Independent fixture helper: no production encoder dependency.
        size = len(content)
        if size < 128:
            length = bytes([size])
        elif size < 256:
            length = b"\x81" + bytes([size])
        else:
            length = b"\x82" + size.to_bytes(2, "big")
        return bytes([tag]) + length + content

    def strict(self, raw):
        return validate_tree(parse_der(raw))

    def resource(self, fn, *args):
        self.assert_failure("malformed", "resource_limit", fn, *args)

    def test_set_of_wire_order_not_numeric_order(self):
        raw = bytes.fromhex("310a0201010201ff02020080")
        children = decode_value(parse_der(raw), 0x31)
        self.assertEqual(tuple(map(decode_value, children)), (1, -1, 128))
        self.assertEqual(b"".join(c.raw for c in children), raw[2:])
        bad = parse_der(bytes.fromhex("3106020102020101"))
        self.assert_failure("non_der", "canonical", decode_value, bad, 0x31)
        # SET vs SET OF is not inferred by the generic tree walker.
        self.assertIs(validate_tree(bad), bad)

    def test_set_of_duplicate_encodings_and_empty(self):
        raw = bytes.fromhex("3106020101020101")
        self.assertEqual([x.raw for x in decode_value(parse_der(raw))],
                         [b"\x02\x01\x01"] * 2)
        self.assertEqual(decode_value(parse_der(b"\x31\x00")), ())

    def test_implicit_set_of_order_and_raw(self):
        raw = bytes.fromhex("a006020101020102")
        node = parse_der(raw)
        self.assertEqual(tuple(map(decode_value, decode_implicit(node, 0, 0x31))), (1, 2))
        self.assertEqual(node.raw, raw)
        bad = parse_der(bytes.fromhex("a006020102020101"))
        self.assertIs(validate_tree(bad), bad)
        self.assert_failure("non_der", "canonical", decode_implicit, bad, 0, 0x31)
        self.assertEqual(tuple(map(decode_value, decode_implicit(bad, 0, 0x30))), (2, 1))

    def test_nested_primitive_validation_and_error_locality(self):
        for raw, kind, reason in (("3005a003010101", "non_der", "canonical"),
                                  ("3005a003050100", "malformed", "structural")):
            node = parse_der(bytes.fromhex(raw))
            (wrapper,) = decode_children(node)
            self.assertEqual(wrapper.raw, bytes.fromhex(raw)[2:])
            self.assert_failure(kind, reason, validate_tree, wrapper)

    def test_nested_trailing_and_truncation(self):
        for raw in ("30053003050002", "3004a0020201", "300430020000"):
            self.assert_failure("malformed", "structural", self.strict, bytes.fromhex(raw))

    def test_encoder_rejects_bad_supplied_elements(self):
        for raw in ("0202ff", "05000500", "300102", "3003050100", "3003010101", "058100"):
            element = bytes.fromhex(raw)
            for fn in (lambda v: der_sequence(v), lambda v: der_set_of(v),
                       lambda v: der_explicit(0, v), lambda v: der_implicit(0, v)):
                with self.subTest(raw=raw, fn=fn):
                    with self.assertRaises(ValueError):
                        fn(element)
        self.assertEqual(der_explicit(0, bytes.fromhex("3003020101")),
                         bytes.fromhex("a0053003020101"))

    def test_opaque_implicit_values_are_not_guessed(self):
        node = parse_der(bytes.fromhex("800101"))
        self.assertIs(validate_tree(node), node)
        self.assertEqual(decode_implicit(node, 0, 0x02), 1)
        self.assert_failure("non_der", "canonical", decode_implicit, node, 0, 0x01)
        octets = parse_der(bytes.fromhex("040202ff"))
        self.assertIs(validate_tree(octets), octets)  # not nested DER by default

    def test_explicit_single_child_canonical_content(self):
        wrapper = parse_der(bytes.fromhex("a00402020001"))
        child = decode_explicit(wrapper, 0)
        self.assert_failure("malformed", "structural", decode_value, child, 0x02)
        self.assert_failure("malformed", "structural", validate_tree, wrapper)

    def test_additional_universal_tag_forms(self):
        for raw in ("2a00", "0900", "0800", "0b00", "1d00"):
            if raw == "0900":  # REAL zero; opaque but structurally permitted
                self.assertEqual(parse_der(bytes.fromhex(raw)).raw, bytes.fromhex(raw))
                continue
            self.assert_failure("malformed", "structural", parse_der, bytes.fromhex(raw))
        for raw in ("3600", "3e00", "3300", "2300"):
            self.assert_failure("non_der", "canonical", parse_der, bytes.fromhex(raw))

    def test_constructed_context_and_private_tags_not_inferred(self):
        for raw in ("a0020500", "e0020500", "60020500"):
            node = self.strict(bytes.fromhex(raw))
            self.assertTrue(node.constructed)
            self.assertEqual(decode_children(node)[0].raw, b"\x05\x00")

    def test_unsupported_typed_encoding_reason(self):
        for raw in ("160178", "9f81000178"):
            node = parse_der(bytes.fromhex(raw))
            self.assert_failure("malformed", "unsupported", decode_value, node)
        self.assert_failure("non_der", "canonical", parse_der, b"\x30\x80")

    def test_more_invalid_utf8_and_printable(self):
        for raw in ("0c02c080", "0c03eda080", "0c04f4908080", "0c02e282", "13017f", "1301ff"):
            self.assert_failure("malformed", "structural", self.strict, bytes.fromhex(raw))

    def test_more_time_boundaries(self):
        valid = self.strict(self.wire(0x18, b"20000229000000Z"))
        self.assertEqual(decode_value(valid), datetime(2000, 2, 29, tzinfo=timezone.utc))
        for tag, text in ((0x18, b"21000229000000Z"), (0x17, b"261231235960Z"),
                          (0x18, b"20500101240000Z"), (0x17, b"261128000000z"),
                          (0x18, b"20500101000000.Z")):
            self.assert_failure("malformed", "structural", self.strict, self.wire(tag, text))
        for text in (b"2050010100Z", b"20500101000000+07", b"20500101000000.0Z"):
            self.assert_failure("non_der", "canonical", self.strict, self.wire(0x18, text))

    def test_canonical_fractional_generalized_time(self):
        for text in (b"20500101000000.5Z", b"20500101000000.1234567Z"):
            raw = self.wire(0x18, text)
            node = self.strict(raw)
            self.assertEqual(node.raw, raw)
            self.assert_failure("malformed", "unsupported", decode_value, node)
        node = parse_der(self.wire(0x18, b"20500101000000.123456Z"))
        self.assertEqual(decode_value(node, allow_fractional=True),
                         datetime(2050, 1, 1, microsecond=123456, tzinfo=timezone.utc))
        node = parse_der(self.wire(0x18, b"20500101000000.1234567Z"))
        self.assert_failure("malformed", "unsupported", decode_value, node, allow_fractional=True)
        node = parse_der(self.wire(0x80, b"20500101000000.5Z"))
        self.assertEqual(decode_implicit(node, 0, 0x18, allow_fractional=True).microsecond, 500000)

    def test_unsupported_calendar_representation(self):
        for text in (b"00000101000000Z", b"20161231235960Z"):
            self.assert_failure("malformed", "unsupported", self.strict, self.wire(0x18, text))
        self.assert_failure("malformed", "structural", self.strict,
                            self.wire(0x18, b"20161231125960Z"))

    def test_unsupported_schema_tag_reason(self):
        node = parse_der(bytes.fromhex("9f81000178"))
        self.assert_failure("malformed", "unsupported", decode_explicit, node, 128)
        self.assert_failure("malformed", "unsupported", decode_implicit, node, 128, 0x04)
        self.assert_failure("malformed", "unsupported", decode_implicit,
                            parse_der(bytes.fromhex("800178")), 0, 0x16)

    def test_input_size_limit(self):
        # read_tlv parses one TLV in a bounded buffer, not the entire stream.
        data = b"\x05\x00" + b"\x00" * (MAX_INPUT_SIZE - 2)
        element, end = read_tlv(data, 0, 2)
        self.assertEqual((element.raw, end), (b"\x05\x00", 2))
        self.resource(read_tlv, data + b"\x00", 0, 2)

    def test_element_length_limit(self):
        data = b"x" * MAX_ELEMENT_LENGTH
        node = self.strict(self.wire(0x04, data))
        self.assertEqual(node.value, data)
        self.resource(parse_der, self.wire(0x04, data + b"x"))
        self.assert_failure("malformed", "structural", parse_der, b"\x04\x82\xff\xff")

    def test_length_octet_limit(self):
        at = bytes([0x04, 0x80 | MAX_LENGTH_OCTETS]) + b"\x00" * (MAX_LENGTH_OCTETS - 1) + b"\x01x"
        self.assert_failure("non_der", "canonical", parse_der, at)
        above = bytes([0x04, 0x80 | (MAX_LENGTH_OCTETS + 1)]) + b"\x00" * MAX_LENGTH_OCTETS + b"\x01x"
        self.resource(parse_der, above)
        self.assert_failure("malformed", "structural", parse_der, above[:3])
        self.resource(parse_der, b"\x04\xfe" + b"\x00" * 126)

    def test_high_tag_octet_limit(self):
        at = b"\x9f\x81" + b"\x80" * (MAX_TAG_OCTETS - 2) + b"\x00\x00"
        node = parse_der(at)
        self.assertEqual(node.raw, at)
        self.assertEqual(node.tag_number, 1 << (7 * (MAX_TAG_OCTETS - 1)))
        above = b"\x9f\x81" + b"\x80" * (MAX_TAG_OCTETS - 1) + b"\x00\x00"
        self.resource(parse_der, above)

    def nested(self, depth):
        raw = b"\x05\x00"
        for _ in range(depth - 1):
            raw = self.wire(0x30, raw)
        return raw

    def test_nesting_depth_limit(self):
        root = self.strict(self.nested(MAX_DEPTH))
        current = root
        for _ in range(MAX_DEPTH - 1):
            current, = decode_children(current)
        self.assertEqual(current.depth, MAX_DEPTH)
        self.assertEqual(current.raw, b"\x05\x00")
        self.resource(self.strict, self.nested(MAX_DEPTH + 1))

    def test_child_count_limit(self):
        raw = self.wire(0x30, b"\x05\x00" * MAX_CHILDREN)
        node = self.strict(raw)
        self.assertEqual(len(decode_children(node)), MAX_CHILDREN)
        self.resource(decode_children, parse_der(self.wire(0x30, b"\x05\x00" * (MAX_CHILDREN + 1))))

    def tree_with_count(self, count):
        # One root + groups with at most MAX_CHILDREN leaf nodes per group.
        remaining = count - 1
        groups = []
        while remaining:
            group_size = min(remaining, MAX_CHILDREN + 1)
            groups.append(self.wire(0x30, b"\x05\x00" * (group_size - 1)))
            remaining -= group_size
        return self.wire(0x30, b"".join(groups))

    def test_total_elements_limit_and_repeat_reads(self):
        root = self.strict(self.tree_with_count(MAX_TOTAL_ELEMENTS))
        self.assertIs(validate_tree(root), root)  # repeat visits are not double counted
        self.resource(self.strict, self.tree_with_count(MAX_TOTAL_ELEMENTS + 1))

    def test_total_elements_shared_across_lazy_branches(self):
        root = parse_der(self.tree_with_count(MAX_TOTAL_ELEMENTS + 1))
        groups = decode_children(root)
        for group in groups[:-1]:
            decode_children(group)
        self.resource(decode_children, groups[-1])

    def test_oid_component_limit(self):
        component = b"\x81" + b"\x80" * (MAX_OID_COMPONENT_OCTETS - 2) + b"\x00"
        raw = self.wire(0x06, b"\x2a" + component)
        self.assertEqual(decode_value(self.strict(raw)), "1.2." + str(1 << (7 * (MAX_OID_COMPONENT_OCTETS - 1))))
        self.resource(self.strict, self.wire(0x06, b"\x2a\x81" + b"\x80" * (MAX_OID_COMPONENT_OCTETS - 1) + b"\x00"))
        self.resource(self.strict, self.wire(0x06, b"\x2a\x81" + b"\x80" * MAX_OID_COMPONENT_OCTETS))

    def test_oid_arc_count_limit(self):
        raw = self.wire(0x06, b"\x2a" + b"\x01" * (MAX_OID_ARCS - 2))
        self.assertEqual(len(decode_value(self.strict(raw)).split(".")), MAX_OID_ARCS)
        self.resource(self.strict, self.wire(0x06, b"\x2a" + b"\x01" * (MAX_OID_ARCS - 1)))

    def test_oid_content_size_limit(self):
        component = b"\x81" + b"\x80" * (MAX_OID_COMPONENT_OCTETS - 2) + b"\x00"
        whole, rest = divmod(MAX_OID_SIZE, len(component))
        content = component * whole
        if rest:
            content += b"\x01" if rest == 1 else b"\x81" + b"\x80" * (rest - 2) + b"\x00"
        self.assertEqual(len(content), MAX_OID_SIZE)
        self.assertEqual(self.strict(self.wire(0x06, content)).value, content)
        self.resource(self.strict, self.wire(0x06, content + b"\x01"))

    def test_medimo_slot_size_and_raw_preservation(self):
        # Synthetic full-size DER element, not a CMS implementation.
        raw = b"\x30\x82\x1f\xfc\x04\x82\x1f\xf8" + b"x" * 8184
        self.assertEqual(len(raw), 8192)
        node = self.strict(raw)
        child, = decode_children(node)
        self.assertEqual(child.raw, raw[4:])
        self.assertEqual(node.raw, raw)
        self.assertEqual(raw[child.start:child.end], child.raw)


if __name__ == "__main__":
    unittest.main()