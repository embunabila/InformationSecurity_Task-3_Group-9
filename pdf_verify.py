
"""PDF digital signature extraction and verification."""

import io

from pypdf import PdfReader
from pypdf.errors import PdfReadError

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

                if byte_range is not None:
                    try:
                        byte_range = [
                            int(value) for value in byte_range
                        ]
                    except (TypeError, ValueError):
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

    Note:
        This validates the ByteRange structure and gap encoding only.
        It does not yet prove that the gap belongs to the correct
        signature dictionary.
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
