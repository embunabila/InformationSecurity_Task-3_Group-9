"""Bounded DER encoder and decoder for Medimo's X.509 and CMS profiles."""

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


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
    # Validate the complete supplied TLV and its visible constructed tree.
    # Opaque primitive content and schema-specific rules remain caller-owned.
    _require_bytes(element)
    validate_tree(parse_der(element))
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

# --- DER decoder ---
# Application limits, not ASN.1/DER limits. The CMS slot is 8192 bytes.
MAX_INPUT_SIZE = 32768
MAX_ELEMENT_LENGTH = 16384
MAX_DEPTH = 32  # root is depth 1
MAX_CHILDREN = 128
MAX_TOTAL_ELEMENTS = 1024  # includes the root
MAX_LENGTH_OCTETS = 4
MAX_TAG_OCTETS = 5  # base-128 groups after the initial identifier octet
MAX_OID_ARCS = 32  # includes the two arcs represented by first subidentifier
MAX_OID_COMPONENT_OCTETS = 10
MAX_OID_SIZE = 256


@dataclass
class _ParseBudget:
    # Count unique input spans, so re-reading a child does not spend budget.
    seen: set = field(default_factory=set)

    def register(self, start, end):
        span = (start, end)
        if span not in self.seen:
            if len(self.seen) >= MAX_TOTAL_ELEMENTS:
                raise _resource("Too many DER elements")
            self.seen.add(span)


class DerError(ValueError):
    """Two contract kinds; reason distinguishes local policy rejection.

    non_der identifies a DER rule violation, not proof of complete valid BER.
    malformed also carries unsupported/resource_limit reasons for compatibility.
    """

    def __init__(self, kind, message, *, reason=None):
        if kind not in ("malformed", "non_der"):
            raise ValueError("Unknown DerError kind")
        super().__init__(message)
        self.kind = kind
        self.reason = reason or ("canonical" if kind == "non_der" else "structural")


@dataclass(frozen=True)
class DerElement:
    tag: int                 # complete identifier octets, as an integer
    identifier: bytes
    tag_class: int           # 0=universal, 1=application, 2=context, 3=private
    tag_number: int
    constructed: bool
    length: int
    value: bytes
    raw: bytes
    start: int
    value_start: int
    end: int                 # exclusive; offsets relative to original input
    depth: int = field(default=1, compare=False, repr=False)
    _budget: _ParseBudget = field(default_factory=_ParseBudget, compare=False, repr=False)


def _malformed(message):
    return DerError("malformed", message)


def _non_der(message):
    return DerError("non_der", message)


def _resource(message):
    return DerError("malformed", message, reason="resource_limit")


def _unsupported(message):
    return DerError("malformed", message, reason="unsupported")


# Known universal tag forms; unrecognized tags remain opaque at TLV level.
_PRIMITIVE_ONLY = frozenset({1, 2, 5, 6, 9, 10, 13, 14, 31, 32, 33, 34, 35, 36})
_CONSTRUCTED_ONLY = frozenset({8, 11, 16, 17, 29})
_DER_PRIMITIVE_STRINGS = frozenset({3, 4, 7, 12, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 30})


def _read_tlv(data, offset, limit, base=0, *, depth=1, budget=None):
    if depth > MAX_DEPTH:
        raise _resource("DER nesting depth exceeded")
    if budget is None:
        budget = _ParseBudget()
    start = offset
    if offset >= limit:
        raise _malformed("Missing tag")

    first = data[offset]
    offset += 1
    tag_class = first >> 6
    constructed = bool(first & 0x20)
    number = first & 0x1f

    # Preserve valid high-tag-number identifiers as opaque TLVs.
    # Typed decoders never interpret them as a supported low-number type.
    if number == 31:
        number = 0
        first_group = True
        groups = 0
        while True:
            if offset >= limit:
                raise _malformed("Truncated high-tag-number identifier")
            octet = data[offset]
            offset += 1
            if first_group and (octet & 0x7f) == 0:
                raise _malformed("Non-minimal high-tag-number identifier")
            groups += 1
            if groups > MAX_TAG_OCTETS:
                raise _resource("High-tag-number identifier too long")
            first_group = False
            number = (number << 7) | (octet & 0x7f)
            if not octet & 0x80:
                break
        if number < 31:
            raise _malformed("High-tag-number form used for a low tag")

    identifier = data[start:offset]
    if tag_class == 0 and number in (0, 15):
        raise _malformed("Unexpected EOC or reserved universal tag")

    if tag_class == 0 and (
        (number in _PRIMITIVE_ONLY and constructed)
        or (number in _CONSTRUCTED_ONLY and not constructed)
    ):
        raise _malformed("Invalid primitive/constructed form for ASN.1 type")

    if offset >= limit:
        raise _malformed("Missing length")
    first_length = data[offset]
    offset += 1
    non_minimal = False

    if first_length < 128:
        length = first_length
    elif first_length == 0x80:
        if not constructed:
            raise _malformed("Primitive element has indefinite length")
        # Stop here: this is not a BER validator and does not inspect EOC.
        raise _non_der("Indefinite length is not permitted in DER")
    elif first_length == 0xff:
        raise _malformed("Reserved length octet")
    else:
        count = first_length & 0x7f
        if count > limit - offset:
            raise _malformed("Truncated long-form length")
        if count > MAX_LENGTH_OCTETS:
            raise _resource("Too many length octets")
        encoded_length = data[offset:offset + count]
        offset += count
        length = int.from_bytes(encoded_length, "big")
        non_minimal = encoded_length[0] == 0 or length < 128

    if length > limit - offset:
        raise _malformed("Value exceeds enclosing boundary")
    if length > MAX_ELEMENT_LENGTH:
        raise _resource("DER element content too large")
    if non_minimal:
        raise _non_der("Non-minimal length encoding")

    if tag_class == 0 and number in _DER_PRIMITIVE_STRINGS and constructed:
        raise _non_der("Constructed string encoding is not DER")

    end = offset + length
    budget.register(base + start, base + end)
    element = DerElement(
        tag=int.from_bytes(identifier, "big"),
        identifier=identifier,
        tag_class=tag_class,
        tag_number=number,
        constructed=constructed,
        length=length,
        value=data[offset:end],
        raw=data[start:end],
        start=base + start,
        value_start=base + offset,
        end=base + end,
        depth=depth,
        _budget=budget,
    )
    return element, end


def read_tlv(data, offset=0, end=None):
    """Read one TLV within [offset, end); return (element, next_offset)."""
    if not isinstance(data, bytes):
        raise _malformed("DER input must be bytes")
    if len(data) > MAX_INPUT_SIZE:
        raise _resource("DER input too large")
    if end is None:
        end = len(data)
    if (type(offset) is not int or type(end) is not int
            or not 0 <= offset <= end <= len(data)):
        raise _malformed("Invalid parsing boundaries")
    return _read_tlv(data, offset, end)


def parse_der(data):
    """Read exactly one outer TLV, without recursively decoding children."""
    element, end = read_tlv(data)
    if end != len(data):
        raise _malformed("Trailing bytes after DER element")
    return element


def decode_children(element):
    """Read immediate children; no child can cross its parent's value."""
    if not isinstance(element, DerElement) or not element.constructed:
        raise _malformed("Expected a constructed element")
    children = []
    offset = 0
    while offset < element.length:
        if len(children) >= MAX_CHILDREN:
            raise _resource("Too many children in DER element")
        child, offset = _read_tlv(
            element.value, offset, element.length, element.value_start,
            depth=element.depth + 1, budget=element._budget,
        )
        children.append(child)
    return tuple(children)


def _decode_oid(value):
    if not value:
        raise _malformed("Empty OBJECT IDENTIFIER")
    if len(value) > MAX_OID_SIZE:
        raise _resource("OBJECT IDENTIFIER content too large")
    arcs = []
    number = 0
    groups = 0
    at_start = True
    for octet in value:
        if at_start and octet == 0x80:
            # Minimal subidentifier encoding is required even by BER.
            raise _malformed("Non-minimal OID subidentifier")
        groups += 1
        if groups > MAX_OID_COMPONENT_OCTETS:
            raise _resource("OID subidentifier too large")
        number = (number << 7) | (octet & 0x7f)
        at_start = False
        if not octet & 0x80:
            if len(arcs) >= MAX_OID_ARCS - 1:
                raise _resource("Too many OID arcs")
            arcs.append(number)
            number = 0
            groups = 0
            at_start = True
    if not at_start:
        raise _malformed("Truncated OID subidentifier")
    first = arcs.pop(0)
    if first < 40:
        prefix = (0, first)
    elif first < 80:
        prefix = (1, first - 40)
    else:
        prefix = (2, first - 80)
    try:
        return ".".join(str(arc) for arc in (*prefix, *arcs))
    except ValueError as exc:
        raise _malformed("OID cannot be represented as decimal") from exc


def _decode_time(value, tag, *, validate_only=False, allow_fractional=False):
    # Parse common BER time forms to distinguish non-DER from malformed
    # calendar values. The typed Medimo profile accepts whole seconds only.
    if tag == 0x17:
        match = re.fullmatch(rb"([0-9]{2})([0-9]{8})([0-9]{2})?(Z|[+-][0-9]{4})", value)
    else:
        match = re.fullmatch(
            rb"([0-9]{4})([0-9]{6})([0-9]{2})?([0-9]{2})?([.,][0-9]+)?(Z|[+-][0-9]{2}(?:[0-9]{2})?)?",
            value,
        )
    if match is None:
        raise _malformed("Invalid or unsupported time syntax")

    if tag == 0x17:
        y, fields, seconds, zone = match.groups()
        month, day, hour, minute = (int(fields[i:i + 2]) for i in range(0, 8, 2))
        year = int(y)
        year += 1900 if year >= 50 else 2000
        second = int(seconds or b"00")
        full_precision = seconds is not None
        fraction = None
    else:
        y, fields, minutes, seconds, fraction, zone = match.groups()
        year = int(y)
        month, day, hour = (int(fields[i:i + 2]) for i in range(0, 6, 2))
        minute = int(minutes or b"00")
        second = int(seconds or b"00")
        full_precision = minutes is not None and seconds is not None

    # Python datetime cannot represent ISO year zero or a leap second.
    # Do not silently normalize either. UTCTime seconds are strictly 00-59.
    unusual_year = tag == 0x18 and year == 0
    leap_second = tag == 0x18 and second == 60
    try:
        result = datetime(400 if unusual_year else year, month, day, hour,
                          minute, 59 if leap_second else second, tzinfo=timezone.utc)
        if zone not in (None, b"Z"):
            if int(zone[1:3]) > 23 or int(zone[3:5] or b"00") > 59:
                raise ValueError("Invalid time offset")
    except ValueError as exc:
        raise _malformed("Invalid calendar time") from exc

    if zone != b"Z" or not full_precision:
        raise _non_der("Time must include seconds and use UTC Z notation")
    if fraction is not None and (fraction.startswith(b",") or fraction.endswith(b"0")):
        raise _non_der("Non-canonical GeneralizedTime fraction")
    if leap_second and (hour, minute) != (23, 59):
        raise _malformed("Invalid UTC leap-second position")
    if unusual_year or leap_second:
        raise _unsupported("Calendar value outside supported datetime representation")
    if fraction is not None:
        # DER permits canonical fractions of arbitrary precision. Validate
        # the lexical form without converting or rounding it in tree checks.
        if validate_only:
            return None
        if not allow_fractional:
            raise _unsupported("Fractional seconds outside legacy time profile")
        digits = fraction[1:]
        if len(digits) > 6:
            raise _unsupported("Fraction exceeds datetime precision; use raw value")
        return result.replace(microsecond=int(digits.ljust(6, b"0")))
    return result


_SUPPORTED_TAGS = frozenset({
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x0c, 0x13, 0x17, 0x18, 0x30, 0x31,
})


def _decode_as(element, tag, *, allow_fractional=False):
    value = element.value
    if tag in (0x30, 0x31):
        children = decode_children(element)
        if tag == 0x31:
            _check_set_of_order(children)
        return children
    if tag == 0x01:
        if len(value) != 1:
            raise _malformed("BOOLEAN requires one content octet")
        if value not in (b"\x00", b"\xff"):
            raise _non_der("Non-canonical BOOLEAN TRUE")
        return value == b"\xff"
    if tag == 0x02:
        if not value:
            raise _malformed("Empty INTEGER")
        if len(value) > 1 and (
            (value[0] == 0 and not value[1] & 0x80)
            or (value[0] == 0xff and value[1] & 0x80)
        ):
            raise _malformed("Redundant INTEGER sign octet")
        return int.from_bytes(value, "big", signed=True)
    if tag == 0x03:
        if not value or value[0] > 7:
            raise _malformed("Invalid BIT STRING unused-bit count")
        unused, bits = value[0], value[1:]
        if not bits and unused:
            raise _malformed("Empty BIT STRING has unused bits")
        if bits and bits[-1] & ((1 << unused) - 1):
            raise _non_der("Non-zero BIT STRING padding")
        return bits, unused
    if tag == 0x04:
        return value
    if tag == 0x05:
        if value:
            raise _malformed("NULL must have empty content")
        return None
    if tag == 0x06:
        return _decode_oid(value)
    if tag in (0x0c, 0x13):
        try:
            text = value.decode("utf-8" if tag == 0x0c else "ascii")
        except UnicodeError as exc:
            raise _malformed("Invalid string encoding") from exc
        if tag == 0x13 and any(c not in _PRINTABLE_CHARS for c in text):
            raise _malformed("Invalid PrintableString character")
        return text
    if tag in (0x17, 0x18):
        return _decode_time(value, tag, allow_fractional=allow_fractional)
    raise _unsupported("No typed decoder for this tag")


def decode_value(element, expected_tag=None, *, allow_fractional=False):
    """Decode a supported universal type; 0x31 means SET OF in this API.

    Whole-second time remains the default for Stage 2b compatibility.
    allow_fractional=True enables exact datetime fractions up to six digits.
    """
    if not isinstance(element, DerElement):
        raise _malformed("Expected a DerElement")
    tag = element.tag if expected_tag is None else expected_tag
    if type(tag) is not int or tag not in _SUPPORTED_TAGS:
        raise _unsupported("Unsupported typed decoder tag")
    if element.tag != tag:
        # Constructed string encodings can be BER but are forbidden in DER.
        if tag in (0x03, 0x04, 0x0c, 0x13, 0x17, 0x18) and element.tag == tag | 0x20:
            raise _non_der("Constructed string encoding is not DER")
        raise _malformed("Unexpected ASN.1 tag")
    return _decode_as(element, tag, allow_fractional=allow_fractional)


def decode_explicit(element, number):
    """Return the one child of an explicitly tagged context wrapper."""
    if not isinstance(element, DerElement) or type(number) is not int or number < 0:
        raise _malformed("Invalid explicit context tag request")
    if number > 30:
        raise _unsupported("High-number explicit context tags are not supported")
    if element.tag != (0xa0 | number):
        raise _malformed("Unexpected explicit context tag")
    children = decode_children(element)
    if len(children) != 1:
        raise _malformed("Explicit tag requires exactly one child")
    return children[0]


def decode_implicit(element, number, universal_tag, *, allow_fractional=False):
    """Interpret context-tagged content using a caller-supplied schema tag."""
    if (not isinstance(element, DerElement) or type(number) is not int
            or number < 0 or type(universal_tag) is not int):
        raise _malformed("Invalid implicit context tag request")
    if number > 30 or universal_tag not in _SUPPORTED_TAGS:
        raise _unsupported("Unsupported implicit tag or schema type")
    expected = 0x80 | (universal_tag & 0x20) | number
    if element.tag != expected:
        if universal_tag in (0x03, 0x04, 0x0c, 0x13, 0x17, 0x18) and element.tag == (expected | 0x20):
            raise _non_der("Constructed implicit string encoding is not DER")
        raise _malformed("Unexpected implicit context tag")
    # No reconstructed TLV: preserve the original element and raw bytes.
    return _decode_as(element, universal_tag, allow_fractional=allow_fractional)


def _check_set_of_order(children):
    # Complete canonical TLVs cannot be proper prefixes of one another.
    # Thus ordinary bytes ordering is sufficient for X.690 11.6.
    if any(a.raw > b.raw for a, b in zip(children, children[1:])):
        raise _non_der("SET OF elements are not in canonical order")


def validate_tree(element):
    """Validate every visible TLV and supported universal primitive.

    Does not infer SET vs SET OF, implicit types, or encapsulated DER from
    opaque values. Call on each schema-defined subtree at the proper layer.
    Returns the original element; no bytes are re-encoded.
    """
    if not isinstance(element, DerElement):
        raise _malformed("Expected a DerElement")
    stack = [element]
    while stack:
        current = stack.pop()
        if current.constructed:
            stack.extend(reversed(decode_children(current)))
        elif current.tag_class == 0 and current.tag in _SUPPORTED_TAGS:
            if current.tag in (0x17, 0x18):
                _decode_time(current.value, current.tag, validate_only=True)
            else:
                _decode_as(current, current.tag)
    return element
