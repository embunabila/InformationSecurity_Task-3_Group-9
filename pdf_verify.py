
"""PDF digital signature extraction and verification."""

import io

from pypdf import PdfReader
from pypdf.errors import PdfReadError
from pypdf.generic import (
    DictionaryObject,
    IndirectObject,
    NameObject,
    read_object,
)

from share_errors import (
    InvalidPdfError,
    InvalidSignatureError,
    UnsupportedSignatureError,
)


def _resolve_pdf_object(obj):
    """Resolve an indirect PDF object."""
    if obj is None:
        return None

    if hasattr(obj, "get_object"):
        return obj.get_object()

    return obj


def _extract_field_signatures(fields, parent_name="", inherited_type=None):
    """Recursively extract non-empty PDF signature fields."""
    signatures = []

    for field_ref in fields:
        field = _resolve_pdf_object(field_ref)

        if not hasattr(field, "get"):
            continue

        field_type = field.get("/FT", inherited_type)

        partial_name = field.get("/T")
        if partial_name:
            partial_name = str(partial_name)
            field_name = (
                f"{parent_name}.{partial_name}"
                if parent_name
                else partial_name
            )
        else:
            field_name = parent_name

        if str(field_type) == "/Sig":
            signature_value = _resolve_pdf_object(field.get("/V"))

            # Ignore empty signature fields.
            if signature_value is not None:
                if not hasattr(signature_value, "get"):
                    continue

                sub_filter = signature_value.get("/SubFilter")
                byte_range = signature_value.get("/ByteRange")

                # Preserve original values. Type validation happens later.
                if byte_range is not None:
                    try:
                        byte_range = list(byte_range)
                    except TypeError:
                        byte_range = None

                signatures.append({
                    "field_name": field_name,
                    "sub_filter": (
                        str(sub_filter) if sub_filter is not None else None
                    ),
                    "byte_range": byte_range,
                })

        children = field.get("/Kids")
        if children:
            signatures.extend(
                _extract_field_signatures(
                    children,
                    parent_name=field_name,
                    inherited_type=field_type,
                )
            )

    return signatures



def _extract_signature_field_references(
    fields,
    parent_name="",
    inherited_type=None,
):
    """
    Extract original references to non-empty signature dictionaries.

    Returns:
        list[dict]: Signature field names, references, and ByteRange.
    """
    signatures = []

    for field_ref in fields:
        field = _resolve_pdf_object(field_ref)

        if not hasattr(field, "get"):
            continue

        field_type = field.get("/FT", inherited_type)

        partial_name = field.get("/T")
        if partial_name:
            partial_name = str(partial_name)
            field_name = (
                f"{parent_name}.{partial_name}"
                if parent_name
                else partial_name
            )
        else:
            field_name = parent_name

        if str(field_type) == "/Sig" and "/V" in field:
            signature_ref = field.raw_get("/V")
            signature_value = _resolve_pdf_object(signature_ref)

            if signature_value is not None:
                if not hasattr(signature_value, "get"):
                    raise InvalidSignatureError(
                        "Invalid signature dictionary."
                    )

                byte_range = signature_value.get("/ByteRange")

                if byte_range is not None:
                    try:
                        byte_range = list(byte_range)
                    except TypeError:
                        byte_range = None

                signatures.append({
                    "field_name": field_name,
                    "field_ref": field_ref,
                    "signature_ref": signature_ref,
                    "byte_range": byte_range,
                })

        children = field.get("/Kids")
        if children:
            signatures.extend(
                _extract_signature_field_references(
                    children,
                    parent_name=field_name,
                    inherited_type=field_type,
                )
            )

    return signatures



def extract_signatures(pdf_bytes):
    """
    Extract non-empty digital signature fields from a PDF.

    Returns:
        list[dict]: Extracted signature metadata.

    Raises:
        InvalidPdfError: If the PDF cannot be parsed.
    """
    if not isinstance(pdf_bytes, bytes) or not pdf_bytes:
        raise InvalidPdfError("Invalid PDF document.")

    try:
        reader = PdfReader(io.BytesIO(pdf_bytes), strict=True)

        if reader.is_encrypted:
            raise InvalidPdfError("Invalid PDF document.")

        root = _resolve_pdf_object(reader.trailer.get("/Root"))

        if root is None:
            raise InvalidPdfError("Invalid PDF document.")

        acro_form = _resolve_pdf_object(root.get("/AcroForm"))

        if acro_form is None:
            return []

        fields = acro_form.get("/Fields", [])

        return _extract_field_signatures(fields)

    except InvalidPdfError:
        raise
    except (PdfReadError, ValueError, TypeError, KeyError, OSError):
        raise InvalidPdfError("Invalid PDF document.") from None


def _validate_byte_range(pdf_bytes, byte_range):
    """
    Validate the structure of a PDF signature ByteRange.

    Returns:
        tuple: (a, b, c, contents_hex)

    Raises:
        InvalidSignatureError: If the ByteRange or Contents gap is invalid.
        UnsupportedSignatureError: If the Contents encoding is unsupported.
    """
    if not isinstance(pdf_bytes, bytes):
        raise InvalidSignatureError("Invalid ByteRange.")

    if not isinstance(byte_range, (list, tuple)):
        raise InvalidSignatureError("Invalid ByteRange.")

    if len(byte_range) != 4:
        raise InvalidSignatureError("Invalid ByteRange.")

    for number in byte_range:
        if isinstance(number, bool) or not isinstance(number, int):
            raise InvalidSignatureError("Invalid ByteRange.")

        if number < 0:
            raise InvalidSignatureError("Invalid ByteRange.")

    zero, a, b, c = byte_range

    if zero != 0 or a >= b:
        raise InvalidSignatureError("Invalid ByteRange.")

    if b + c > len(pdf_bytes):
        raise InvalidSignatureError("Invalid ByteRange.")

    # The excluded Contents token must include its angle brackets.
    if pdf_bytes[a:a + 1] != b"<":
        raise InvalidSignatureError("Invalid Contents boundary.")

    if pdf_bytes[b - 1:b] != b">":
        raise InvalidSignatureError("Invalid Contents boundary.")

    contents_hex = pdf_bytes[a + 1:b - 1]

    if not contents_hex:
        raise InvalidSignatureError("Empty signature Contents.")

    # Whitespace inside the hex string is not supported.
    pdf_whitespace = b"\x00\t\n\f\r "

    if any(char in pdf_whitespace for char in contents_hex):
        raise UnsupportedSignatureError(
            "Whitespace in signature Contents is unsupported."
        )

    # Odd-length hexadecimal strings are unsupported.
    if len(contents_hex) % 2 != 0:
        raise UnsupportedSignatureError(
            "Odd-length signature Contents is unsupported."
        )

    valid_hex = b"0123456789abcdefABCDEF"

    if any(char not in valid_hex for char in contents_hex):
        raise InvalidSignatureError(
            "Signature Contents contains invalid hexadecimal data."
        )

    return a, b, c, contents_hex


def _skip_pdf_whitespace_and_comments(stream):
    """Skip PDF whitespace and comments."""
    whitespace = b"\x00\t\n\f\r "

    while True:
        char = stream.read(1)

        if not char:
            return

        if char in whitespace:
            continue

        if char == b"%":
            while True:
                char = stream.read(1)

                if not char or char in (b"\r", b"\n"):
                    break

            continue

        stream.seek(-1, 1)
        return


def _read_raw_signature_dictionary(pdf_bytes, reader, signature_ref):
    """
    Read a signature dictionary using its exact indirect object reference.

    Returns:
        dict: Raw Contents token positions and parsed ByteRange.

    Raises:
        UnsupportedSignatureError: If the object representation is unsupported.
        InvalidSignatureError: If the signature dictionary is malformed.
    """
    if not isinstance(signature_ref, IndirectObject):
        raise UnsupportedSignatureError(
            "Direct signature dictionaries are unsupported."
        )

    object_id = signature_ref.idnum
    generation = signature_ref.generation

    # Signature dictionaries in object streams are not supported.
    if (
        generation == 0
        and object_id in reader.xref_objStm
    ):
        raise UnsupportedSignatureError(
            "Compressed signature dictionaries are unsupported."
        )

    generation_xref = reader.xref.get(generation, {})
    offset = generation_xref.get(object_id)

    if not isinstance(offset, int) or offset < 0:
        raise InvalidSignatureError(
            "Signature object was not found in the cross-reference table."
        )

    if offset >= len(pdf_bytes):
        raise InvalidSignatureError(
            "Signature object offset is outside the PDF."
        )

    stream = io.BytesIO(pdf_bytes[offset:])

    actual_id, actual_generation = reader.read_object_header(stream)

    if (
        actual_id != object_id
        or actual_generation != generation
    ):
        raise InvalidSignatureError(
            "Signature object reference does not match its cross-reference entry."
        )

    _skip_pdf_whitespace_and_comments(stream)

    if stream.read(2) != b"<<":
        raise UnsupportedSignatureError(
            "Signature object is not a supported PDF dictionary."
        )

    seen_keys = set()
    contents_start = None
    contents_end = None
    contents_token = None
    byte_range_value = None

    while True:
        _skip_pdf_whitespace_and_comments(stream)

        marker = stream.read(2)

        if marker == b">>":
            break

        if not marker:
            raise InvalidSignatureError(
                "Signature dictionary is incomplete."
            )

        stream.seek(-2, 1)

        key = read_object(stream, reader)

        if not isinstance(key, NameObject):
            raise InvalidSignatureError(
                "Invalid signature dictionary key."
            )

        key_name = str(key)

        # Reject duplicate security-sensitive entries.
        if key_name in seen_keys:
            if key_name in ("/Contents", "/ByteRange"):
                raise InvalidSignatureError(
                    f"Duplicate {key_name} entry in signature dictionary."
                )

        seen_keys.add(key_name)

        _skip_pdf_whitespace_and_comments(stream)

        value_start = stream.tell()
        value = read_object(stream, reader)
        value_end = stream.tell()

        if key_name == "/Contents":
            if contents_start is not None:
                raise InvalidSignatureError(
                    "Duplicate Contents entry in signature dictionary."
                )

            raw_token = pdf_bytes[
                offset + value_start:offset + value_end
            ]

            # Save the token first. Validate its format after checking
            # all dictionary keys for duplicates.
            contents_start = offset + value_start
            contents_end = offset + value_end
            contents_token = raw_token

        elif key_name == "/ByteRange":
            if byte_range_value is not None:
                raise InvalidSignatureError(
                    "Duplicate ByteRange entry in signature dictionary."
                )

            if not isinstance(value, (list, tuple)):
                raise InvalidSignatureError(
                    "Signature ByteRange is not an array."
                )

            byte_range_value = list(value)

    if contents_start is None or byte_range_value is None:
        raise InvalidSignatureError(
            "Signature dictionary is missing Contents or ByteRange."
        )

    # Validate Contents representation only after duplicate detection.
    if (
        len(contents_token) < 2
        or not contents_token.startswith(b"<")
        or contents_token.startswith(b"<<")
        or not contents_token.endswith(b">")
    ):
        raise UnsupportedSignatureError(
            "Signature Contents is not a supported hexadecimal string."
        )

    return {
        "byte_range": byte_range_value,
        "contents_start": contents_start,
        "contents_end": contents_end,
        "contents_token": contents_token,
    }


def _same_indirect_reference(first, second):
    """Check whether two indirect references identify the same PDF object."""
    return (
        isinstance(first, IndirectObject)
        and isinstance(second, IndirectObject)
        and first.idnum == second.idnum
        and first.generation == second.generation
    )


def _validate_signature_binding(pdf_bytes, reader, field_info):
    """
    Validate the binding between a signature field, its dictionary,
    ByteRange, and raw Contents token in the signed revision.

    Returns:
        dict: Validated signature binding information.

    Raises:
        InvalidSignatureError: If the binding is inconsistent.
        UnsupportedSignatureError: If the PDF representation is unsupported.
    """
    field_ref = field_info.get("field_ref")
    field_name = field_info.get("field_name")
    expected_signature_ref = field_info.get("signature_ref")
    current_byte_range = field_info.get("byte_range")

    if not isinstance(field_ref, IndirectObject):
        raise UnsupportedSignatureError(
            "Direct signature fields are unsupported."
        )

    if not isinstance(expected_signature_ref, IndirectObject):
        raise UnsupportedSignatureError(
            "Direct signature dictionaries are unsupported."
        )

    # Resolve the corresponding field in the current PDF.
    current_field_ref = IndirectObject(
        field_ref.idnum,
        field_ref.generation,
        reader,
    )

    current_field = _resolve_pdf_object(current_field_ref)

    if current_field is None:
        raise InvalidSignatureError(
            "Signature field was not found in the current PDF."
        )

    if not isinstance(current_field, DictionaryObject):
        raise InvalidSignatureError(
            "Signature field is not a dictionary."
        )

    if str(current_field.get("/FT")) != "/Sig":
        raise InvalidSignatureError(
            "Referenced object is not a signature field."
        )

    if "/V" not in current_field:
        raise InvalidSignatureError(
            "Signature field has no signature dictionary."
        )

    # Preserve the indirect reference from the current field.
    signature_ref = current_field.raw_get("/V")

    if not isinstance(signature_ref, IndirectObject):
        raise UnsupportedSignatureError(
            "Direct signature dictionaries are unsupported."
        )

    # The current field must still point to the expected signature object.
    if not _same_indirect_reference(
        signature_ref,
        expected_signature_ref,
    ):
        raise InvalidSignatureError(
            "Signature field reference changed after signing."
        )

    # Obtain ByteRange from the extracted signature metadata.
    if current_byte_range is None:
        raise InvalidSignatureError(
            "Signature ByteRange is missing."
        )

    # Validate ByteRange against the current PDF.
    _, b, c, _ = _validate_byte_range(
        pdf_bytes,
        current_byte_range,
    )

    signed_revision_length = b + c
    signed_revision = pdf_bytes[:signed_revision_length]

    if not signed_revision:
        raise InvalidSignatureError("Empty signed revision.")

    # Parse the PDF as it existed at the end of the signed revision.
    try:
        signed_reader = PdfReader(
            io.BytesIO(signed_revision),
            strict=True,
        )

        if signed_reader.is_encrypted:
            raise InvalidSignatureError(
                "Encrypted signed revisions are unsupported."
            )

        root = _resolve_pdf_object(
            signed_reader.trailer.get("/Root")
        )

        if root is None:
            raise InvalidSignatureError(
                "Signed revision has no document root."
            )

        acro_form = _resolve_pdf_object(
            root.get("/AcroForm")
        )

        if acro_form is None:
            raise InvalidSignatureError(
                "Signature field is missing from the signed revision."
            )

        fields = acro_form.get("/Fields", [])

        signed_fields = _extract_signature_field_references(
            fields
        )

    except InvalidSignatureError:
        raise
    except (
        PdfReadError,
        ValueError,
        TypeError,
        KeyError,
        OSError,
    ):
        raise InvalidSignatureError(
            "Cannot parse the signed revision."
        ) from None

    # Find the exact original field object in the signed revision.
    matching_fields = [
        item
        for item in signed_fields
        if _same_indirect_reference(
            item["field_ref"],
            field_ref,
        )
    ]

    if len(matching_fields) != 1:
        raise InvalidSignatureError(
            "Signature field does not uniquely exist in the signed revision."
        )

    signed_field = matching_fields[0]

    if signed_field["field_name"] != field_name:
        raise InvalidSignatureError(
            "Signature field name changed after signing."
        )

    signed_signature_ref = signed_field["signature_ref"]

    # The original field must point to the same signature dictionary.
    if not _same_indirect_reference(
        signed_signature_ref,
        signature_ref,
    ):
        raise InvalidSignatureError(
            "Signature field reference does not match the signed revision."
        )

    # Read the raw signature dictionary from the signed revision,
    # not from the latest incremental revision.
    signed_raw = _read_raw_signature_dictionary(
        signed_revision,
        signed_reader,
        signed_signature_ref,
    )

    if signed_raw["byte_range"] != current_byte_range:
        raise InvalidSignatureError(
            "Signature ByteRange changed after signing."
        )

    # Validate the original ByteRange against the signed revision itself.
    a, signed_b, signed_c, _ = _validate_byte_range(
        signed_revision,
        signed_raw["byte_range"],
    )

    if signed_b + signed_c != len(signed_revision):
        raise InvalidSignatureError(
            "ByteRange does not end at the signed revision boundary."
        )

    # The raw Contents token must occupy exactly the excluded ByteRange.
    if (
        signed_raw["contents_start"] != a
        or signed_raw["contents_end"] != signed_b
        or signed_raw["contents_token"] != signed_revision[a:signed_b]
    ):
        raise InvalidSignatureError(
            "ByteRange does not match the signature dictionary Contents."
        )

    return {
        "byte_range": signed_raw["byte_range"],
        "contents_start": signed_raw["contents_start"],
        "contents_end": signed_raw["contents_end"],
        "contents_token": signed_raw["contents_token"],
        "signed_revision_length": len(signed_revision),
    }