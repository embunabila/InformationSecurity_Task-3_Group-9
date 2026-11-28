"""Minimal DER encoder for Medimo's X.509 and CMS profiles."""

import re
from datetime import datetime, timedelta


_PRINTABLE_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789 '()+,-./:=?"
)


def _require_bytes(value):
    if not isinstance(value, bytes):
        raise ValueError("DER value must be bytes")


def _check_tag(tag):
    if type(tag) is not int or not 0 <= tag <= 255:
        raise ValueError("Tag must be a single octet")

    if tag in (0x00, 0x20) or tag & 0x1F == 0x1F:
        raise ValueError(
            "EOC and high-tag-number form are not supported"
        )


def der_length(length):
    if type(length) is not int or length < 0:
        raise ValueError(
            "Length must be a non-negative integer"
        )

    if length < 128:
        return bytes([length])

    count = (length.bit_length() + 7) // 8

    if count > 126:
        raise ValueError(
            "Length exceeds DER length-of-length limit"
        )

    return (
        bytes([0x80 | count])
        + length.to_bytes(count, "big")
    )


def der_tlv(tag, value):
    _check_tag(tag)
    _require_bytes(value)

    return (
        bytes([tag])
        + der_length(len(value))
        + value
    )


def der_integer(value):
    if type(value) is not int:
        raise ValueError("INTEGER requires an integer")

    bits = (
        value.bit_length()
        if value >= 0
        else (~value).bit_length()
    )

    size = max(1, (bits + 8) // 8)

    return der_tlv(
        0x02,
        value.to_bytes(size, "big", signed=True),
    )


def der_boolean(value):
    if type(value) is not bool:
        raise ValueError("BOOLEAN requires bool")

    return der_tlv(
        0x01,
        b"\xff" if value else b"\x00",
    )


def der_bit_string(data, unused_bits=0, *, named=False):
    _require_bytes(data)

    if (
        type(unused_bits) is not int
        or not 0 <= unused_bits <= 7
    ):
        raise ValueError("Invalid unused bit count")

    if type(named) is not bool:
        raise ValueError("named must be bool")

    if not data and unused_bits:
        raise ValueError(
            "Empty BIT STRING cannot have unused bits"
        )

    if data and data[-1] & ((1 << unused_bits) - 1):
        raise ValueError("Unused bits must be zero")

    if named:
        data = data.rstrip(b"\x00")

        if data:
            last = data[-1]
            unused_bits = (
                (last & -last).bit_length() - 1
            )
        else:
            unused_bits = 0

    return der_tlv(
        0x03,
        bytes([unused_bits]) + data,
    )


def der_octet_string(data):
    return der_tlv(0x04, data)


def der_null():
    return der_tlv(0x05, b"")


def _base128(value):
    groups = [value & 0x7F]
    value >>= 7

    while value:
        groups.append(0x80 | (value & 0x7F))
        value >>= 7

    return bytes(reversed(groups))


def der_oid(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))+",
        value,
    ):
        raise ValueError(
            "OID must contain dotted decimal arcs"
        )

    arcs = [
        int(arc)
        for arc in value.split(".")
    ]

    first, second = arcs[:2]

    if first > 2 or (first < 2 and second > 39):
        raise ValueError(
            "Invalid first or second OID arc"
        )

    content = _base128(40 * first + second)

    content += b"".join(
        _base128(arc)
        for arc in arcs[2:]
    )

    return der_tlv(0x06, content)


def der_utf8_string(value):
    if not isinstance(value, str):
        raise ValueError("UTF8String requires str")

    return der_tlv(
        0x0C,
        value.encode("utf-8", errors="strict"),
    )


def der_printable_string(value):
    if not isinstance(value, str) or any(
        char not in _PRINTABLE_CHARS
        for char in value
    ):
        raise ValueError("Invalid PrintableString")

    return der_tlv(
        0x13,
        value.encode("ascii"),
    )


def _utc_seconds(value):
    if (
        not isinstance(value, datetime)
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError(
            "Time must be a timezone-aware UTC datetime"
        )

    if value.microsecond != 0:
        raise ValueError(
            "Medimo time must have whole-second precision"
        )

    return (
        f"{value.month:02d}{value.day:02d}"
        f"{value.hour:02d}{value.minute:02d}"
        f"{value.second:02d}Z"
    )


def der_utc_time(value):
    suffix = _utc_seconds(value)

    if not 1950 <= value.year <= 2049:
        raise ValueError(
            "UTCTime year must be 1950-2049"
        )

    return der_tlv(
        0x17,
        f"{value.year % 100:02d}{suffix}".encode("ascii"),
    )


def der_generalized_time(value):
    suffix = _utc_seconds(value)

    return der_tlv(
        0x18,
        f"{value.year:04d}{suffix}".encode("ascii"),
    )


def _encoded_element(element):
    # Only accepts trusted TLVs produced by the encoder.
    # Full structural validation belongs to the decoder.
    _require_bytes(element)

    if len(element) < 2:
        raise ValueError(
            "Expected an encoded DER element"
        )

    _check_tag(element[0])

    return element


def der_sequence(*elements):
    return der_tlv(
        0x30,
        b"".join(
            _encoded_element(e)
            for e in elements
        ),
    )


def der_set_of(*elements):
    encoded = sorted(
        _encoded_element(e)
        for e in elements
    )

    return der_tlv(
        0x31,
        b"".join(encoded),
    )


def _context_tag(number, constructed):
    if type(number) is not int or not 0 <= number <= 30:
        raise ValueError(
            "Context tag number must be 0-30"
        )

    return (
        0x80
        | (0x20 if constructed else 0)
        | number
    )


def der_explicit(number, element):
    return der_tlv(
        _context_tag(number, True),
        _encoded_element(element),
    )


def der_implicit(number, element):
    element = _encoded_element(element)

    tag = _context_tag(
        number,
        bool(element[0] & 0x20),
    )

    return bytes([tag]) + element[1:]