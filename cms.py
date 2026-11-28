"""Detached CMS SignedData builder and parser for Medimo."""

from Crypto.PublicKey import RSA

from certificate import parse_certificate

from der import (
    DerError,
    read_tlv,
    decode_children,
    decode_value,
    decode_explicit,
    decode_implicit,
    validate_tree,
    der_integer,
    der_oid,
    der_null,
    der_octet_string,
    der_sequence,
    der_set_of,
    der_explicit,
    der_implicit,
    der_utc_time,
)

from share_errors import (
    InvalidSignatureError,
    UnsupportedSignatureError,
)

from signing_keys import rsa_sign, rsa_verify


# ============================================================
# CMS constants
# ============================================================

_ID_DATA = "1.2.840.113549.1.7.1"
_ID_SIGNED_DATA = "1.2.840.113549.1.7.2"

_SHA256 = "2.16.840.1.101.3.4.2.1"

_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"

_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3"
_ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
_ATTR_SIGNING_TIME = "1.2.840.113549.1.9.5"

_REQUIRED_ATTRIBUTES = frozenset({
    _ATTR_CONTENT_TYPE,
    _ATTR_MESSAGE_DIGEST,
    _ATTR_SIGNING_TIME,
})

_SUPPORTED_SIGNATURE_ALGORITHMS = frozenset({
    _RSA_ENCRYPTION,
    _SHA256_WITH_RSA,
})

_DIGEST_SIZE = 32
_SIGNING_KEY_BITS = 3072
_PDF_CONTENTS_CAPACITY = 8192


# ============================================================
# Stage 7a: CMS builder
# ============================================================


def _digest_algorithm():
    """SHA-256 AlgorithmIdentifier with absent parameters."""

    return der_sequence(
        der_oid(_SHA256),
    )


def _signature_algorithm():
    """rsaEncryption AlgorithmIdentifier with NULL parameters."""

    return der_sequence(
        der_oid(_RSA_ENCRYPTION),
        der_null(),
    )


def _build_attribute(oid, value):
    """Encode a single-valued CMS Attribute."""

    return der_sequence(
        der_oid(oid),
        der_set_of(value),
    )


def _build_signed_attributes(
    document_digest,
    signing_time,
):
    """Build canonical DER SignedAttributes using universal SET OF."""

    return der_set_of(
        _build_attribute(
            _ATTR_CONTENT_TYPE,
            der_oid(_ID_DATA),
        ),
        _build_attribute(
            _ATTR_MESSAGE_DIGEST,
            der_octet_string(document_digest),
        ),
        _build_attribute(
            _ATTR_SIGNING_TIME,
            der_utc_time(signing_time),
        ),
    )


def _validate_builder_certificate(
    certificate_der,
    private_key,
    signing_time,
):
    """Validate the certificate used for Medimo's own signing operation."""

    try:
        parsed = parse_certificate(certificate_der)

    except (
        InvalidSignatureError,
        UnsupportedSignatureError,
    ) as exc:
        raise ValueError(
            "Invalid or unsupported signing certificate"
        ) from exc

    certificate_key = RSA.import_key(
        parsed["public_key_pem"]
    )

    if (
        certificate_key.has_private()
        or certificate_key.size_in_bits() != _SIGNING_KEY_BITS
        or certificate_key.n != private_key.n
        or certificate_key.e != private_key.e
    ):
        raise ValueError(
            "Certificate public key does not match signing private key"
        )

    # This check is only for Medimo's own signing certificate.
    # External CA-issued certificates are not subject to this
    # requirement in the CMS parser.
    if not rsa_verify(
        parsed["public_key_pem"],
        parsed["tbs_der"],
        parsed["signature"],
    ):
        raise ValueError(
            "Invalid certificate self-signature"
        )

    if not (
        parsed["not_before"]
        <= signing_time
        <= parsed["not_after"]
    ):
        raise ValueError(
            "Signing time is outside certificate validity"
        )

    return parsed


def build_cms_signed_data(
    document_digest,
    certificate_der,
    private_key,
    signing_time,
) -> bytes:
    """Build one detached CMS SignedData object under Medimo's profile."""

    if (
        not isinstance(document_digest, bytes)
        or len(document_digest) != _DIGEST_SIZE
    ):
        raise ValueError(
            "Document digest must be exactly 32 bytes"
        )

    if (
        not isinstance(certificate_der, bytes)
        or not certificate_der
    ):
        raise ValueError(
            "Certificate must be non-empty DER bytes"
        )

    if (
        not isinstance(private_key, RSA.RsaKey)
        or not private_key.has_private()
        or private_key.size_in_bits() != _SIGNING_KEY_BITS
    ):
        raise ValueError(
            "An RSA-3072 private key is required"
        )

    # The existing time encoder enforces:
    # - timezone-aware UTC datetime
    # - whole-second precision
    # - year 1950 through 2049
    #
    # Do not silently round or truncate timestamps here.
    signed_attrs_der = _build_signed_attributes(
        document_digest,
        signing_time,
    )

    certificate = _validate_builder_certificate(
        certificate_der,
        private_key,
        signing_time,
    )

    digest_algorithm = _digest_algorithm()
    signature_algorithm = _signature_algorithm()

    # issuerAndSerialNumber uses the certificate's original
    # issuer DER, not a reconstructed distinguished name.
    signer_identifier = der_sequence(
        certificate["issuer_der"],
        der_integer(certificate["serial"]),
    )

    # RFC 5652 section 5.4:
    # The signature covers the universal SET OF encoding,
    # including tag 0x31 and the original DER length octets.
    signature = rsa_sign(
        private_key,
        signed_attrs_der,
    )

    # Replace the universal SET OF tag with [0] IMPLICIT
    # for the SignerInfo wire representation.
    signed_attrs_wire = der_implicit(
        0,
        signed_attrs_der,
    )

    signer_info = der_sequence(
        der_integer(1),
        signer_identifier,
        digest_algorithm,
        signed_attrs_wire,
        signature_algorithm,
        der_octet_string(signature),
    )

    # CertificateSet is [0] IMPLICIT SET OF CertificateChoices.
    # Medimo embeds exactly one X.509 certificate.
    certificates = der_implicit(
        0,
        der_set_of(certificate_der),
    )

    # eContent is deliberately absent for detached CMS.
    encap_content_info = der_sequence(
        der_oid(_ID_DATA),
    )

    signed_data = der_sequence(
        der_integer(1),
        der_set_of(digest_algorithm),
        encap_content_info,
        certificates,
        der_set_of(signer_info),
    )

    content_info = der_sequence(
        der_oid(_ID_SIGNED_DATA),
        der_explicit(0, signed_data),
    )

    if len(content_info) > _PDF_CONTENTS_CAPACITY:
        raise ValueError(
            "CMS exceeds the 8192-byte PDF signature placeholder"
        )

    return content_info


# ============================================================
# Stage 7b: Parser helpers and scoped DER error mapping
# ============================================================


def _invalid(message):
    raise InvalidSignatureError(message)


def _unsupported(message):
    raise UnsupportedSignatureError(message)


def _raise_invalid_der(exc, scope):
    """Map all DER errors in protected data to invalid."""

    raise InvalidSignatureError(
        f"Invalid {scope} DER ({exc.kind}/{exc.reason})"
    ) from exc


def _sequence(element, count=None):
    fields = decode_value(element, 0x30)

    if count is not None and len(fields) != count:
        _invalid("Unexpected SEQUENCE field count")

    return fields


def _read_version(element):
    version = decode_value(element, 0x02)

    if not 0 <= version <= 5:
        _invalid("Invalid CMS version")

    return version


def _read_algorithm(element, supported_oids):
    """Read an AlgorithmIdentifier and enforce its supported profile."""

    validate_tree(element)

    fields = _sequence(element)

    if len(fields) not in (1, 2):
        _invalid("Malformed AlgorithmIdentifier")

    oid = decode_value(fields[0], 0x06)

    if oid not in supported_oids:
        _unsupported(
            f"Unsupported CMS algorithm: {oid}"
        )

    # Supported SHA-256 and RSA identifiers accept either
    # absent parameters or an exact DER NULL.
    if len(fields) == 2:
        decode_value(fields[1], 0x05)

    return oid


def _scoped_children(
    element,
    protected_child,
    protected_scope,
):
    """Decode immediate children while preserving DER error ownership.

    Normal parsing uses decode_children, retaining the decoder's
    shared depth, child-count and total-element budgets.

    If a child header itself violates DER, decode_children raises
    before returning that child. A bounded diagnostic pass locates
    the failing header solely to classify the error.

    The diagnostic pass never supplies successfully parsed children
    and never bypasses a failed resource-limit check.
    """

    try:
        return decode_children(element)

    except DerError as exc:
        if exc.kind != "non_der":
            raise

        offset = 0
        index = 0

        while offset < len(element.value):
            first_tag = element.value[offset]

            try:
                _, next_offset = read_tlv(
                    element.value,
                    offset,
                )

            except DerError:
                if protected_child(index, first_tag):
                    _raise_invalid_der(
                        exc,
                        protected_scope,
                    )

                break

            offset = next_offset
            index += 1

        # This was an outer CMS DER violation.
        raise


def _read_issuer_name(element):
    """Validate the RDNSequence shape without re-encoding the name."""

    validate_tree(element)

    rdns = _sequence(element)

    if not rdns:
        _invalid("Empty signer issuer name")

    for rdn in rdns:
        attributes = decode_value(rdn, 0x31)

        if not attributes:
            _invalid("Empty relative distinguished name")

        for attribute in attributes:
            oid, _ = _sequence(
                attribute,
                count=2,
            )

            decode_value(oid, 0x06)

    return element.raw


def _read_signer_identifier(element, certificate):
    """Validate and match issuerAndSerialNumber against the certificate."""

    # SubjectKeyIdentifier is a legitimate alternative in CMS,
    # but it is outside Medimo's supported signer identifier profile.
    if element.tag == 0x80:
        if not element.value:
            _invalid("Empty subject key identifier")

        _unsupported(
            "SubjectKeyIdentifier signer identifiers are unsupported"
        )

    issuer, serial_element = _sequence(
        element,
        count=2,
    )

    issuer_der = _read_issuer_name(issuer)

    serial = decode_value(
        serial_element,
        0x02,
    )

    if serial <= 0:
        _invalid("Invalid signer serial number")

    # Contract explicitly classifies nonmatching sid as unsupported.
    if (
        issuer_der != certificate["issuer_der"]
        or serial != certificate["serial"]
    ):
        _unsupported(
            "Signer identifier does not match embedded certificate"
        )


def _read_encap_content_info(element):
    fields = _sequence(element)

    if len(fields) not in (1, 2):
        _invalid("Malformed EncapsulatedContentInfo")

    content_type = decode_value(
        fields[0],
        0x06,
    )

    if len(fields) == 2:
        content = decode_explicit(
            fields[1],
            0,
        )

        validate_tree(content)
        decode_value(content, 0x04)

        _unsupported(
            "Attached CMS content is unsupported"
        )

    if content_type != _ID_DATA:
        _unsupported(
            "Unsupported encapsulated content type"
        )

    return content_type


def _read_certificates(element):
    """Read the one supported X.509 CertificateChoice."""

    if element.tag != 0xa0:
        _invalid("Malformed CertificateSet")

    # A non-DER certificate header belongs to the certificate,
    # not to the surrounding CMS encoding.
    certificates = _scoped_children(
        element,
        protected_child=lambda index, tag: tag == 0x30,
        protected_scope="certificate",
    )

    if len(certificates) != 1:
        _unsupported(
            "Exactly one embedded certificate is required"
        )

    certificate_element = certificates[0]

    if certificate_element.tag != 0x30:
        if certificate_element.tag in (
            0xa0,
            0xa1,
            0xa2,
            0xa3,
        ):
            validate_tree(certificate_element)

            _unsupported(
                "Unsupported CMS certificate choice"
            )

        _invalid("Malformed certificate choice")

    try:
        # Validate the certificate subtree with the original
        # CMS decoder budget before parsing its own schema.
        validate_tree(certificate_element)

    except DerError as exc:
        _raise_invalid_der(exc, "certificate")

    certificate_der = certificate_element.raw

    # parse_certificate applies X.509-specific schema rules
    # and its own contract-defined error mapping.
    parsed = parse_certificate(
        certificate_der
    )

    return certificate_der, parsed


def _read_signed_attributes(
    element,
    expected_content_type,
):
    """Read signed attributes without reconstructing their DER encoding."""

    try:
        validate_tree(element)

        attributes = decode_implicit(
            element,
            0,
            0x31,
        )

        if not attributes:
            _invalid("Empty signedAttrs")

        values = {}

        for attribute in attributes:
            oid_element, value_set = _sequence(
                attribute,
                count=2,
            )

            oid = decode_value(
                oid_element,
                0x06,
            )

            attribute_values = decode_value(
                value_set,
                0x31,
            )

            if not attribute_values:
                _invalid("Empty attribute value SET")

            # Additional signed attributes are allowed if their
            # generic Attribute structure is valid. Their raw bytes
            # remain covered by the document signature.
            if oid not in _REQUIRED_ATTRIBUTES:
                continue

            if oid in values:
                _invalid(
                    f"Duplicate mandatory signed attribute: {oid}"
                )

            if len(attribute_values) != 1:
                _invalid(
                    f"Invalid mandatory attribute cardinality: {oid}"
                )

            value = attribute_values[0]

            if oid == _ATTR_CONTENT_TYPE:
                values[oid] = decode_value(
                    value,
                    0x06,
                )

            elif oid == _ATTR_MESSAGE_DIGEST:
                digest = decode_value(
                    value,
                    0x04,
                )

                if len(digest) != _DIGEST_SIZE:
                    _invalid(
                        "messageDigest must be exactly 32 bytes"
                    )

                values[oid] = digest

            elif oid == _ATTR_SIGNING_TIME:
                if value.tag not in (0x17, 0x18):
                    _invalid(
                        "signingTime must be UTCTime or GeneralizedTime"
                    )

                # Existing decoder returns timezone-aware UTC
                # datetime and rejects unsupported time precision.
                values[oid] = decode_value(value)

        if _ATTR_CONTENT_TYPE not in values:
            _invalid("Missing contentType signed attribute")

        if _ATTR_MESSAGE_DIGEST not in values:
            _invalid("Missing messageDigest signed attribute")

        if values[_ATTR_CONTENT_TYPE] != expected_content_type:
            _invalid(
                "contentType does not match eContentType"
            )

        if _ATTR_SIGNING_TIME not in values:
            _unsupported(
                "Missing signingTime signed attribute"
            )

    except DerError as exc:
        # SignedAttrs is a DER-protected subtree.
        # Even non_der errors are invalid here.
        _raise_invalid_der(
            exc,
            "signedAttrs",
        )

    # Do not sort, rebuild or re-encode the received attributes.
    signed_attrs_der = (
        b"\x31" + element.raw[1:]
    )

    return (
        signed_attrs_der,
        values[_ATTR_MESSAGE_DIGEST],
        values[_ATTR_SIGNING_TIME],
    )


def _read_signer_info(
    element,
    certificate,
    expected_content_type,
):
    if element.tag != 0x30:
        _invalid("Malformed SignerInfo")

    # SignedAttrs is field index 3 when present.
    # Its header must also obey the signed-data DER policy.
    fields = _scoped_children(
        element,
        protected_child=lambda index, tag: (
            index == 3 and tag == 0xa0
        ),
        protected_scope="signedAttrs",
    )

    if len(fields) < 5:
        _invalid("Missing SignerInfo fields")

    version = _read_version(fields[0])

    _read_signer_identifier(
        fields[1],
        certificate,
    )

    _read_algorithm(
        fields[2],
        {_SHA256},
    )

    index = 3
    signed_attrs = None

    if fields[index].tag == 0xa0:
        signed_attrs = fields[index]
        index += 1

    elif fields[index].tag == 0x80:
        _invalid(
            "signedAttrs must be constructed"
        )

    if len(fields) < index + 2:
        _invalid("Missing SignerInfo signature fields")

    _read_algorithm(
        fields[index],
        _SUPPORTED_SIGNATURE_ALGORITHMS,
    )

    signature = decode_value(
        fields[index + 1],
        0x04,
    )

    if not signature:
        _invalid("Empty CMS signature")

    optional = fields[index + 2:]

    if optional:
        if (
            len(optional) != 1
            or optional[0].tag != 0xa1
        ):
            _invalid(
                "Malformed SignerInfo optional fields"
            )

        validate_tree(optional[0])

        unsigned_attributes = decode_implicit(
            optional[0],
            1,
            0x31,
        )

        if not unsigned_attributes:
            _invalid("Empty unsignedAttrs")

        for attribute in unsigned_attributes:
            oid_element, value_set = _sequence(
                attribute,
                count=2,
            )

            decode_value(oid_element, 0x06)

            if not decode_value(value_set, 0x31):
                _invalid(
                    "Empty unsigned attribute value SET"
                )

        _unsupported(
            "Unsigned attributes are outside the supported CMS profile"
        )

    if version != 1:
        _unsupported(
            "Only SignerInfo version 1 is supported"
        )

    if signed_attrs is None:
        _unsupported(
            "SignerInfo without signedAttrs is unsupported"
        )

    (
        signed_attrs_der,
        message_digest,
        signing_time,
    ) = _read_signed_attributes(
        signed_attrs,
        expected_content_type,
    )

    return {
        "signed_attrs_der": signed_attrs_der,
        "message_digest": message_digest,
        "signing_time": signing_time,
        "signature": signature,
    }


# ============================================================
# Stage 7b: CMS parser
# ============================================================


def parse_cms_signed_data(contents_bytes) -> dict:
    """Parse detached CMS and optional zero padding from PDF Contents.

    This function validates structure and extracts original signature
    inputs. It does not verify the document digest, RSA signature,
    certificate trust, signing-time validity or registered identity.
    """

    if (
        not isinstance(contents_bytes, bytes)
        or not contents_bytes
    ):
        _invalid(
            "CMS contents must be non-empty bytes"
        )

    if contents_bytes[0] != 0x30:
        _invalid(
            "ContentInfo must be a SEQUENCE"
        )

    try:
        # read_tlv reads the outer length before padding checks.
        # An indefinite-length outer ContentInfo raises non_der.
        content_info, end = read_tlv(
            contents_bytes
        )

        # Only bytes after the complete definite-length TLV
        # may be treated as PDF placeholder padding.
        if any(contents_bytes[end:]):
            _invalid(
                "Nonzero trailing bytes after CMS"
            )

        content_type, content = _sequence(
            content_info,
            count=2,
        )

        if decode_value(content_type, 0x06) != _ID_SIGNED_DATA:
            _unsupported(
                "CMS content type is not SignedData"
            )

        signed_data = decode_explicit(
            content,
            0,
        )

        fields = _sequence(signed_data)

        if len(fields) < 4:
            _invalid("Missing SignedData fields")

        version = _read_version(fields[0])

        digest_algorithms = decode_value(
            fields[1],
            0x31,
        )

        if len(digest_algorithms) != 1:
            _unsupported(
                "Exactly one digest algorithm is required"
            )

        _read_algorithm(
            digest_algorithms[0],
            {_SHA256},
        )

        expected_content_type = _read_encap_content_info(
            fields[2]
        )

        index = 3

        certificate_set = None

        if fields[index].tag == 0xa0:
            certificate_set = fields[index]
            index += 1

        elif fields[index].tag == 0x80:
            _invalid(
                "CertificateSet must be constructed"
            )

        if index < len(fields) and fields[index].tag == 0xa1:
            crls = fields[index]

            validate_tree(crls)

            if not decode_implicit(crls, 1, 0x31):
                _invalid("Empty RevocationInfoChoices")

            _unsupported(
                "CRLs are outside the supported CMS profile"
            )

        if index != len(fields) - 1:
            _invalid(
                "Unexpected SignedData optional fields"
            )

        signer_infos = decode_value(
            fields[index],
            0x31,
        )

        if len(signer_infos) != 1:
            _unsupported(
                "Exactly one SignerInfo is required"
            )

        if certificate_set is None:
            _unsupported(
                "An embedded certificate is required"
            )

        if version != 1:
            _unsupported(
                "Only SignedData version 1 is supported"
            )

        (
            certificate_der,
            certificate,
        ) = _read_certificates(
            certificate_set
        )

        signer = _read_signer_info(
            signer_infos[0],
            certificate,
            expected_content_type,
        )

        return {
            "certificate_der": certificate_der,
            "signed_attrs_der": signer["signed_attrs_der"],
            "message_digest": signer["message_digest"],
            "signing_time": signer["signing_time"],
            "signature": signer["signature"],
        }

    except DerError as exc:
        # All protected subtree errors have already been
        # translated locally into InvalidSignatureError.
        #
        # Remaining non_der violations are outer CMS encoding
        # violations. The contract classifies these as unsupported.
        if exc.kind == "non_der":
            raise UnsupportedSignatureError(
                f"Unsupported CMS encoding ({exc.reason})"
            ) from exc

        # Includes malformed/structural,
        # malformed/resource_limit and malformed/unsupported.
        raise InvalidSignatureError(
            f"Invalid CMS DER ({exc.kind}/{exc.reason})"
        ) from exc