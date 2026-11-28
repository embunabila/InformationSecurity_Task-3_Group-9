"""Medimo X.509 v3 self-signed certificate builder and parser."""

from datetime import timedelta

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from der import (
    DerError,
    decode_explicit,
    decode_implicit,
    decode_value,
    parse_der,
    validate_tree,
    der_bit_string,
    der_boolean,
    der_explicit,
    der_integer,
    der_null,
    der_octet_string,
    der_oid,
    der_sequence,
    der_set_of,
    der_utc_time,
    der_utf8_string,
)

from share_errors import (
    InvalidSignatureError,
    UnsupportedSignatureError,
)


# ============================================================
# Stage 4a: Certificate builder
# ============================================================


def _generate_serial_number():
    while True:
        raw = get_random_bytes(16)

        serial = int.from_bytes(raw, "big") & (
            (1 << 127) - 1
        )

        if serial != 0:
            return serial


def _signature_algorithm():
    return der_sequence(
        der_oid("1.2.840.113549.1.1.11"),
        der_null(),
    )


def _build_name(username):
    if (
        not isinstance(username, str)
        or not username.strip()
        or len(username) > 64
        or "\x00" in username
    ):
        raise ValueError("Invalid common name")

    organization = der_set_of(
        der_sequence(
            der_oid("2.5.4.10"),
            der_utf8_string("Medimo"),
        )
    )

    common_name = der_set_of(
        der_sequence(
            der_oid("2.5.4.3"),
            der_utf8_string(username),
        )
    )

    return der_sequence(
        organization,
        common_name,
    )


def _build_validity(not_before, not_after):
    before = der_utc_time(not_before)
    after = der_utc_time(not_after)

    if not_after <= not_before:
        raise ValueError(
            "not_after must be later than not_before"
        )

    if not_after - not_before != timedelta(days=730):
        raise ValueError(
            "Certificate validity must be exactly 730 days"
        )

    return der_sequence(before, after)


def _build_extensions():
    basic_constraints = der_sequence(
        der_oid("2.5.29.19"),
        der_boolean(True),
        der_octet_string(
            der_sequence()
        ),
    )

    key_usage = der_sequence(
        der_oid("2.5.29.15"),
        der_boolean(True),
        der_octet_string(
            der_bit_string(
                b"\xc0",
                named=True,
            )
        ),
    )

    return der_explicit(
        3,
        der_sequence(
            basic_constraints,
            key_usage,
        ),
    )


def build_self_signed_certificate(
    private_key,
    username,
    not_before,
    not_after,
) -> bytes:
    """Build a DER certificate under Medimo's self-signed RSA profile."""

    from signing_keys import rsa_sign

    if (
        not isinstance(private_key, RSA.RsaKey)
        or not private_key.has_private()
    ):
        raise ValueError(
            "An RSA private key is required"
        )

    name = _build_name(username)

    validity = _build_validity(
        not_before,
        not_after,
    )

    algorithm = _signature_algorithm()

    spki = private_key.public_key().export_key(
        format="DER"
    )

    tbs_der = der_sequence(
        der_explicit(0, der_integer(2)),
        der_integer(_generate_serial_number()),
        algorithm,
        name,
        validity,
        name,
        spki,
        _build_extensions(),
    )

    signature = rsa_sign(
        private_key,
        tbs_der,
    )

    return der_sequence(
        tbs_der,
        algorithm,
        der_bit_string(signature),
    )


# ============================================================
# Stage 4b: Certificate parser
# ============================================================


_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"

_COMMON_NAME = "2.5.4.3"

_BASIC_CONSTRAINTS = "2.5.29.19"
_KEY_USAGE = "2.5.29.15"


def _sequence(element, *, count=None):
    children = decode_value(element, 0x30)

    if count is not None and len(children) != count:
        raise InvalidSignatureError(
            "Unexpected SEQUENCE field count"
        )

    return children


def _read_algorithm(element):
    fields = _sequence(element)

    if len(fields) not in (1, 2):
        raise InvalidSignatureError(
            "Invalid AlgorithmIdentifier"
        )

    oid = decode_value(fields[0], 0x06)

    # Supported RSA algorithms accept absent or NULL parameters.
    if (
        oid in (_RSA_ENCRYPTION, _SHA256_WITH_RSA)
        and len(fields) == 2
    ):
        decode_value(fields[1], 0x05)

    return oid


def _read_common_name(element):
    if element.tag in (0x0c, 0x13):
        value = decode_value(element)

    elif element.tag in (0x1e, 0x1c):
        # Legacy BMPString and UniversalString alternatives.
        try:
            value = element.value.decode(
                "utf-16-be"
                if element.tag == 0x1e
                else "utf-32-be",
                errors="strict",
            )
        except UnicodeError as exc:
            raise InvalidSignatureError(
                "Invalid legacy common name"
            ) from exc

        if (
            element.tag == 0x1e
            and any(ord(c) > 0xffff for c in value)
        ):
            raise InvalidSignatureError(
                "Invalid BMPString code point"
            )

    elif element.tag == 0x14:
        if not 1 <= element.length <= 64:
            raise InvalidSignatureError(
                "Invalid TeletexString length"
            )

        raise UnsupportedSignatureError(
            "TeletexString common name unsupported"
        )

    else:
        raise InvalidSignatureError(
            "Invalid common name string type"
        )

    if not 1 <= len(value) <= 64:
        raise InvalidSignatureError(
            "Invalid common name"
        )

    return value


def _read_name(element, *, subject=False):
    rdns = _sequence(element)

    if not rdns and not subject:
        raise InvalidSignatureError(
            "Issuer name must not be empty"
        )

    common_names = []

    for rdn in rdns:
        # RDN is SET OF AttributeTypeAndValue.
        # decode_value also checks canonical SET OF ordering.
        attributes = decode_value(rdn, 0x31)

        if not attributes:
            raise InvalidSignatureError(
                "Empty relative distinguished name"
            )

        for attribute in attributes:
            oid, value = _sequence(
                attribute,
                count=2,
            )

            if decode_value(oid, 0x06) == _COMMON_NAME:
                common_names.append(
                    _read_common_name(value)
                )

    if subject:
        # The public contract returns exactly one subject_cn.
        if len(common_names) != 1:
            raise UnsupportedSignatureError(
                "Exactly one subject CN is required"
            )

        return common_names[0]

    return None


def _read_validity(element):
    before, after = _sequence(
        element,
        count=2,
    )

    if (
        before.tag not in (0x17, 0x18)
        or after.tag not in (0x17, 0x18)
    ):
        raise InvalidSignatureError(
            "Invalid certificate time tag"
        )

    not_before = decode_value(before)
    not_after = decode_value(after)

    if not_after < not_before:
        raise InvalidSignatureError(
            "Reversed certificate validity interval"
        )

    return not_before, not_after


def _read_spki(element):
    algorithm, public_bits = _sequence(
        element,
        count=2,
    )

    oid = _read_algorithm(algorithm)

    public_der, unused = decode_value(
        public_bits,
        0x03,
    )

    if not public_der:
        raise InvalidSignatureError(
            "Empty subject public key"
        )

    if oid != _RSA_ENCRYPTION:
        raise UnsupportedSignatureError(
            "Unsupported public key algorithm"
        )

    if unused != 0:
        raise InvalidSignatureError(
            "RSA public key must be octet aligned"
        )

    # SubjectPublicKeyInfo contains an encoded RSAPublicKey.
    # Validate its structure before using RSA.import_key.
    key = validate_tree(
        parse_der(public_der)
    )

    modulus, exponent = _sequence(
        key,
        count=2,
    )

    n = decode_value(modulus, 0x02)
    e = decode_value(exponent, 0x02)

    if (
        n <= 0
        or n % 2 == 0
        or e < 3
        or e >= n
        or e % 2 == 0
    ):
        raise InvalidSignatureError(
            "Invalid RSA public components"
        )

    if not 2048 <= n.bit_length() <= 4096:
        raise UnsupportedSignatureError(
            "Unsupported RSA modulus size"
        )

    try:
        RSA.construct(
            (n, e),
            consistency_check=True,
        )

        imported = RSA.import_key(element.raw)

        if (
            not isinstance(imported, RSA.RsaKey)
            or imported.has_private()
            or (imported.n, imported.e) != (n, e)
        ):
            raise ValueError(
                "Unexpected imported RSA components"
            )

        return imported.export_key(
            format="PEM"
        )

    except (
        ValueError,
        TypeError,
        IndexError,
        OverflowError,
        AttributeError,
    ) as exc:
        raise InvalidSignatureError(
            "Invalid RSA public key"
        ) from exc


def _read_basic_constraints(element):
    fields = list(_sequence(element))
    ca = False

    if fields and fields[0].tag == 0x01:
        ca = decode_value(
            fields.pop(0),
            0x01,
        )

        if not ca:
            raise InvalidSignatureError(
                "DEFAULT FALSE must be omitted"
            )

    if fields:
        if len(fields) != 1 or not ca:
            raise InvalidSignatureError(
                "Invalid BasicConstraints"
            )

        path_length = decode_value(
            fields[0],
            0x02,
        )

        if path_length < 0:
            raise InvalidSignatureError(
                "Negative path length"
            )

    return ca


def _read_key_usage(element):
    bits, unused = decode_value(
        element,
        0x03,
    )

    bit_count = len(bits) * 8 - unused

    # KeyUsage defines nine named bits.
    # DER named BIT STRINGs must omit trailing zero bits.
    if (
        not 1 <= bit_count <= 9
        or not bits[-1] & (1 << unused)
    ):
        raise InvalidSignatureError(
            "Invalid or non-canonical KeyUsage"
        )

    return bits


def _read_extensions(element):
    extensions = _sequence(
        decode_explicit(element, 3)
    )

    if not extensions:
        raise InvalidSignatureError(
            "Empty Extensions sequence"
        )

    seen = set()
    unsupported_critical = False

    for extension in extensions:
        fields = _sequence(extension)

        if len(fields) not in (2, 3):
            raise InvalidSignatureError(
                "Invalid Extension structure"
            )

        oid = decode_value(
            fields[0],
            0x06,
        )

        if oid in seen:
            raise InvalidSignatureError(
                "Duplicate extension OID"
            )

        seen.add(oid)

        critical = False

        if len(fields) == 3:
            critical = decode_value(
                fields[1],
                0x01,
            )

            if not critical:
                raise InvalidSignatureError(
                    "DEFAULT FALSE must be omitted"
                )

        payload = decode_value(
            fields[-1],
            0x04,
        )

        # extnValue contains exactly one DER-encoded value.
        inner = validate_tree(
            parse_der(payload)
        )

        if oid == _BASIC_CONSTRAINTS:
            _read_basic_constraints(inner)

        elif oid == _KEY_USAGE:
            _read_key_usage(inner)

        elif critical:
            unsupported_critical = True

    if unsupported_critical:
        raise UnsupportedSignatureError(
            "Unsupported critical extension"
        )


def _read_tbs_optional(fields, version):
    last_number = 0

    for field in fields:
        if field.tag not in (0x81, 0x82, 0xa3):
            raise InvalidSignatureError(
                "Unexpected TBSCertificate optional field"
            )

        number = field.tag_number

        if number <= last_number:
            raise InvalidSignatureError(
                "Duplicate or out-of-order optional field"
            )

        last_number = number

        if number in (1, 2):
            # issuerUniqueID and subjectUniqueID:
            # IMPLICIT BIT STRING, permitted in v2 and v3.
            if version == 0:
                raise InvalidSignatureError(
                    "Unique ID not allowed in v1"
                )

            bits, _ = decode_implicit(
                field,
                number,
                0x03,
            )

            if not bits:
                raise InvalidSignatureError(
                    "Empty unique identifier"
                )

        else:
            if version != 2:
                raise InvalidSignatureError(
                    "Extensions require X.509 v3"
                )

            _read_extensions(field)


def parse_certificate(certificate_der) -> dict:
    """Parse certificate structure and extract key and metadata.

    This function does not verify certificate signatures,
    establish certificate trust, or validate a PKI chain.
    """

    try:
        outer = validate_tree(
            parse_der(certificate_der)
        )

        tbs, outer_algorithm, signature_element = _sequence(
            outer,
            count=3,
        )

        fields = _sequence(tbs)

        # Version DEFAULT is v1 (INTEGER 0).
        version = 0

        if fields and fields[0].tag == 0xa0:
            version = decode_value(
                decode_explicit(fields[0], 0),
                0x02,
            )

            # Explicit v1 violates DER DEFAULT omission.
            if version not in (1, 2):
                raise InvalidSignatureError(
                    "Invalid or explicitly defaulted version"
                )

            fields = fields[1:]

        if len(fields) < 6:
            raise InvalidSignatureError(
                "Missing TBSCertificate fields"
            )

        (
            serial_element,
            inner_algorithm,
            issuer,
            validity,
            subject,
            spki,
        ) = fields[:6]

        serial = decode_value(
            serial_element,
            0x02,
        )

        if (
            serial <= 0
            or serial_element.length > 20
        ):
            raise InvalidSignatureError(
                "Invalid certificate serial number"
            )

        inner_oid = _read_algorithm(
            inner_algorithm
        )

        outer_oid = _read_algorithm(
            outer_algorithm
        )

        if (
            inner_algorithm.raw != outer_algorithm.raw
            or inner_oid != outer_oid
        ):
            raise InvalidSignatureError(
                "Certificate signature algorithms differ"
            )

        if inner_oid != _SHA256_WITH_RSA:
            raise UnsupportedSignatureError(
                "Unsupported certificate signature algorithm"
            )

        _read_name(issuer)

        subject_cn = _read_name(
            subject,
            subject=True,
        )

        not_before, not_after = _read_validity(
            validity
        )

        public_key_pem = _read_spki(spki)

        signature, unused = decode_value(
            signature_element,
            0x03,
        )

        if not signature or unused != 0:
            raise InvalidSignatureError(
                "Invalid certificate signature BIT STRING"
            )

        _read_tbs_optional(
            fields[6:],
            version,
        )

        return {
            "tbs_der": tbs.raw,
            "signature": signature,
            "public_key_pem": public_key_pem,
            "subject_cn": subject_cn,
            "serial": serial,
            "issuer_der": issuer.raw,
            "not_before": not_before,
            "not_after": not_after,
        }

    except DerError as exc:
        raise InvalidSignatureError(
            f"Invalid certificate DER "
            f"({exc.kind}/{exc.reason})"
        ) from exc