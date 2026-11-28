
import io
from datetime import datetime, timezone

import pytest
from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    NameObject,
    TextStringObject,
)

from pdf_sign import (
    prepare_pdf_for_signing,
    embed_signature,
)
from pdf_verify import (
    _validate_signature_binding,
    extract_signatures,
    _validate_byte_range,
    _read_raw_signature_dictionary,
    _extract_signature_field_references,
)
from share_errors import (
    InvalidPdfError,
    InvalidSignatureError,
    UnsupportedSignatureError,
)

_validate_signature_binding,
_extract_signature_field_references,
SIGNER = "Test Signer"

SIGNING_TIME = datetime(
    2026, 11, 27, 9, 30, 0,
    tzinfo=timezone.utc,
)

# Dummy DER data for extraction testing only.
# This is NOT a valid CMS digital signature.
DUMMY_CMS = b"\x30\x00"


def make_pdf():
    """Create a simple valid PDF without signatures."""
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)

    output = io.BytesIO()
    writer.write(output)

    return output.getvalue()


def make_pdf_with_empty_signature_field():
    """Create a valid PDF containing an empty signature field."""
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)

    signature_field = DictionaryObject({
        NameObject("/FT"): NameObject("/Sig"),
        NameObject("/T"): TextStringObject("TestSignature"),
    })

    acro_form = DictionaryObject({
        NameObject("/Fields"): ArrayObject([signature_field]),
    })

    writer.root_object[NameObject("/AcroForm")] = acro_form

    output = io.BytesIO()
    writer.write(output)

    return output.getvalue()


def make_signed_pdf():
    """Create a PDF containing a dummy embedded signature."""
    original_pdf = make_pdf()

    prepared_pdf, byte_range = prepare_pdf_for_signing(
        original_pdf,
        SIGNER,
        SIGNING_TIME,
    )

    signed_pdf = embed_signature(
        prepared_pdf,
        byte_range,
        DUMMY_CMS,
    )

    return signed_pdf, byte_range


def make_pdf_with_contents(contents_hex):
    """Create a simple byte sequence with a Contents-like gap."""
    prefix = b"prefix"
    suffix = b"suffix"

    pdf_bytes = prefix + b"<" + contents_hex + b">" + suffix

    a = len(prefix)
    b = a + len(contents_hex) + 2
    c = len(suffix)

    return pdf_bytes, [0, a, b, c]


# Signature extraction tests
def test_extract_signatures_without_signature():
    pdf_bytes = make_pdf()

    result = extract_signatures(pdf_bytes)

    assert result == []


def test_extract_signatures_with_empty_signature_field():
    pdf_bytes = make_pdf_with_empty_signature_field()

    result = extract_signatures(pdf_bytes)

    assert result == []


def test_extract_signatures_with_invalid_pdf():
    with pytest.raises(InvalidPdfError):
        extract_signatures(b"not a valid PDF")


def test_extract_signatures_with_empty_bytes():
    with pytest.raises(InvalidPdfError):
        extract_signatures(b"")


def test_extract_signatures_with_filled_signature():
    pdf_bytes, expected_byte_range = make_signed_pdf()

    result = extract_signatures(pdf_bytes)

    assert len(result) == 1

    signature = result[0]

    assert signature["field_name"] == "Medimo-Signature"
    assert signature["sub_filter"] == "/adbe.pkcs7.detached"
    assert signature["byte_range"] == expected_byte_range


# ByteRange validation tests
def test_validate_byte_range_with_valid_contents():
    pdf_bytes, byte_range = make_pdf_with_contents(b"30AA")

    a, b, c, contents_hex = _validate_byte_range(
        pdf_bytes,
        byte_range,
    )

    assert pdf_bytes[a:b] == b"<30AA>"
    assert c == 6
    assert contents_hex == b"30AA"


def test_validate_byte_range_with_signed_pdf():
    pdf_bytes, byte_range = make_signed_pdf()

    a, b, c, contents_hex = _validate_byte_range(
        pdf_bytes,
        byte_range,
    )

    assert pdf_bytes[a:a + 1] == b"<"
    assert pdf_bytes[b - 1:b] == b">"
    assert len(contents_hex) > 0
    assert c == len(pdf_bytes) - b


def test_read_raw_signature_dictionary_matches_byte_range():
    pdf_bytes, byte_range = make_signed_pdf()

    reader = PdfReader(io.BytesIO(pdf_bytes), strict=True)

    root = reader.trailer["/Root"].get_object()
    acro_form = root["/AcroForm"].get_object()

    field_ref = acro_form["/Fields"][0]
    field = field_ref.get_object()

    # Keep the original indirect reference from /V.
    signature_ref = field.raw_get("/V")

    result = _read_raw_signature_dictionary(
        pdf_bytes,
        reader,
        signature_ref,
    )

    a, b, c, _ = _validate_byte_range(pdf_bytes, byte_range)

    assert result["byte_range"] == byte_range
    assert result["contents_start"] == a
    assert result["contents_end"] == b
    assert result["contents_token"] == pdf_bytes[a:b]


@pytest.mark.parametrize(
    "byte_range",
    [
        None,
        [],
        [0, 1, 2],
        [0, 1, 2, 3, 4],

        # Boolean values must not be accepted as integers.
        [False, 1, 2, 3],
        [0, True, 2, 3],
        [0, 1, False, 3],
        [0, 1, 2, True],

        # Non-integer values must be rejected.
        [0, 1.5, 2, 3],
        [0, 1, 2.5, 3],
        [0, 1, 2, 3.5],
        ["0", 1, 2, 3],
        [0, "1", 2, 3],
        [0, 1, "2", 3],
        [0, 1, 2, "3"],

        # Negative or structurally invalid values.
        [0, -1, 2, 3],
        [0, 1, -2, 3],
        [0, 1, 2, -3],
        [1, 1, 2, 3],
        [0, 2, 2, 3],
        [0, 1, 100, 100],
    ],
)
def test_validate_byte_range_with_invalid_values(byte_range):
    pdf_bytes = b"prefix<30AA>suffix"

    with pytest.raises(InvalidSignatureError):
        _validate_byte_range(pdf_bytes, byte_range)



def test_validate_byte_range_with_invalid_opening_bracket():
    pdf_bytes, byte_range = make_pdf_with_contents(b"30AA")

    a = byte_range[1]
    modified_pdf = pdf_bytes[:a] + b"[" + pdf_bytes[a + 1:]

    with pytest.raises(InvalidSignatureError):
        _validate_byte_range(modified_pdf, byte_range)


def test_validate_byte_range_with_invalid_closing_bracket():
    pdf_bytes, byte_range = make_pdf_with_contents(b"30AA")

    b = byte_range[2]
    modified_pdf = pdf_bytes[:b - 1] + b"]" + pdf_bytes[b:]

    with pytest.raises(InvalidSignatureError):
        _validate_byte_range(modified_pdf, byte_range)


def test_validate_byte_range_with_whitespace_in_contents():
    pdf_bytes, byte_range = make_pdf_with_contents(b"30 AA")

    with pytest.raises(UnsupportedSignatureError):
        _validate_byte_range(pdf_bytes, byte_range)


def test_validate_byte_range_with_odd_hex_length():
    pdf_bytes, byte_range = make_pdf_with_contents(b"30A")

    with pytest.raises(UnsupportedSignatureError):
        _validate_byte_range(pdf_bytes, byte_range)


def test_validate_byte_range_with_non_hex_contents():
    pdf_bytes, byte_range = make_pdf_with_contents(b"30G0")

    with pytest.raises(InvalidSignatureError):
        _validate_byte_range(pdf_bytes, byte_range)


def get_signature_context(pdf_bytes):
    """Get the reader and signature object reference from a test PDF."""
    reader = PdfReader(io.BytesIO(pdf_bytes), strict=True)

    root = reader.trailer["/Root"].get_object()
    acro_form = root["/AcroForm"].get_object()

    field_ref = acro_form["/Fields"][0]
    field = field_ref.get_object()

    signature_ref = field.raw_get("/V")

    return reader, signature_ref


def replace_signature_dictionary_key(pdf_bytes, old_key, new_key):
    """Replace a key in the raw signature dictionary without shifting offsets."""
    reader, signature_ref = get_signature_context(pdf_bytes)

    offset = reader.xref[signature_ref.generation][signature_ref.idnum]
    dictionary_end = pdf_bytes.find(b">>", offset)

    position = pdf_bytes.find(old_key, offset, dictionary_end)

    assert position >= 0
    assert len(old_key) == len(new_key)

    return (
        pdf_bytes[:position]
        + new_key
        + pdf_bytes[position + len(old_key):]
    )


def replace_byte_range_start(pdf_bytes, byte_range):
    """Change the ByteRange start offset without changing PDF length."""
    reader, signature_ref = get_signature_context(pdf_bytes)

    offset = reader.xref[signature_ref.generation][signature_ref.idnum]
    dictionary_end = pdf_bytes.find(b">>", offset)

    byte_range_key = pdf_bytes.find(
        b"/ByteRange",
        offset,
        dictionary_end,
    )

    assert byte_range_key >= 0

    array_start = pdf_bytes.find(
        b"[",
        byte_range_key,
        dictionary_end,
    )

    assert array_start >= 0

    original_value = str(byte_range[1]).encode("ascii")
    replacement_value = str(byte_range[1] + 1).encode("ascii")

    assert len(original_value) == len(replacement_value)

    value_position = pdf_bytes.find(
        original_value,
        array_start,
        dictionary_end,
    )

    assert value_position >= 0

    return (
        pdf_bytes[:value_position]
        + replacement_value
        + pdf_bytes[value_position + len(original_value):]
    )

def test_read_raw_signature_dictionary_rejects_duplicate_contents():
    pdf_bytes, _ = make_signed_pdf()

    modified_pdf = replace_signature_dictionary_key(
        pdf_bytes,
        b"/SubFilter",
        b"/Contents ",
    )

    reader, signature_ref = get_signature_context(modified_pdf)

    with pytest.raises(InvalidSignatureError):
        _read_raw_signature_dictionary(
            modified_pdf,
            reader,
            signature_ref,
        )


def test_read_raw_signature_dictionary_rejects_duplicate_byte_range():
    pdf_bytes, _ = make_signed_pdf()

    modified_pdf = replace_signature_dictionary_key(
        pdf_bytes,
        b"/SubFilter",
        b"/ByteRange",
    )

    reader, signature_ref = get_signature_context(modified_pdf)

    with pytest.raises(InvalidSignatureError):
        _read_raw_signature_dictionary(
            modified_pdf,
            reader,
            signature_ref,
        )


def test_read_raw_signature_dictionary_rejects_non_hex_contents():
    pdf_bytes, _ = make_signed_pdf()

    reader, signature_ref = get_signature_context(pdf_bytes)

    original = _read_raw_signature_dictionary(
        pdf_bytes,
        reader,
        signature_ref,
    )

    start = original["contents_start"]
    end = original["contents_end"]

    modified_pdf = (
        pdf_bytes[:start]
        + b"("
        + pdf_bytes[start + 1:end - 1]
        + b")"
        + pdf_bytes[end:]
    )

    modified_reader, modified_ref = get_signature_context(modified_pdf)

    with pytest.raises(UnsupportedSignatureError):
        _read_raw_signature_dictionary(
            modified_pdf,
            modified_reader,
            modified_ref,
        )

def test_extract_signature_field_reference_preserves_original_reference():
    pdf_bytes, _ = make_signed_pdf()

    reader = PdfReader(io.BytesIO(pdf_bytes), strict=True)

    root = reader.trailer["/Root"].get_object()
    acro_form = root["/AcroForm"].get_object()

    fields = acro_form.get("/Fields", [])

    field = fields[0].get_object()
    expected_ref = field.raw_get("/V")

    result = _extract_signature_field_references(fields)

    assert len(result) == 1
    assert result[0]["field_name"] == "Medimo-Signature"
    assert result[0]["signature_ref"] == expected_ref

def test_validate_signature_binding_with_valid_signed_pdf():
    pdf_bytes, byte_range = make_signed_pdf()

    reader = PdfReader(io.BytesIO(pdf_bytes), strict=True)

    root = reader.trailer["/Root"].get_object()
    acro_form = root["/AcroForm"].get_object()
    fields = acro_form.get("/Fields", [])

    field_info = _extract_signature_field_references(fields)[0]

    result = _validate_signature_binding(
        pdf_bytes,
        reader,
        field_info,
    )

    assert result["byte_range"] == byte_range
    assert result["contents_start"] == byte_range[1]
    assert result["contents_end"] == byte_range[2]
    assert result["signed_revision_length"] == len(pdf_bytes)    


def test_validate_signature_binding_rejects_modified_byte_range():
    pdf_bytes, byte_range = make_signed_pdf()

    modified_pdf = replace_byte_range_start(
        pdf_bytes,
        byte_range,
    )

    reader, signature_ref = get_signature_context(modified_pdf)

    field_info = {
        "field_name": "Medimo-Signature",
        "field_ref": reader.trailer["/Root"]
        .get_object()["/AcroForm"]
        .get_object()["/Fields"][0],
        "signature_ref": signature_ref,
    }

    with pytest.raises(InvalidSignatureError):
        _validate_signature_binding(
            modified_pdf,
            reader,
            field_info,
        )



def test_validate_signature_binding_rejects_wrong_field_reference():
    pdf_bytes, _ = make_signed_pdf()

    reader = PdfReader(io.BytesIO(pdf_bytes), strict=True)

    root = reader.trailer["/Root"].get_object()
    acro_form = root["/AcroForm"].get_object()
    fields = acro_form["/Fields"]

    field = fields[0].get_object()
    signature_ref = field.raw_get("/V")

    # Use the document root as an incorrect field reference.
    wrong_field_ref = reader.trailer.raw_get("/Root")

    field_info = {
        "field_name": "Medimo-Signature",
        "field_ref": wrong_field_ref,
        "signature_ref": signature_ref,
    }

    with pytest.raises(InvalidSignatureError):
        _validate_signature_binding(
            pdf_bytes,
            reader,
            field_info,
        )


def test_validate_signature_binding_with_incremental_update():
    pdf_bytes, _ = make_signed_pdf()

    reader = PdfReader(io.BytesIO(pdf_bytes), strict=True)

    writer = PdfWriter(reader, incremental=True)
    writer.add_metadata({
        "/Subject": "Modified after signing",
    })

    output = io.BytesIO()
    writer.write(output)

    modified_pdf = output.getvalue()

    assert modified_pdf.startswith(pdf_bytes)
    assert len(modified_pdf) > len(pdf_bytes)

    # Ambil field reference dari PDF sebelum incremental update.
    original_reader = PdfReader(
        io.BytesIO(pdf_bytes),
        strict=True,
    )
    original_root = original_reader.trailer["/Root"].get_object()
    original_acro_form = original_root["/AcroForm"].get_object()
    original_fields = original_acro_form["/Fields"]

    field_info = _extract_signature_field_references(
        original_fields
    )[0]

    # Validasi binding terhadap PDF yang sudah mendapat incremental update.
    modified_reader = PdfReader(
        io.BytesIO(modified_pdf),
        strict=True,
    )

    result = _validate_signature_binding(
        modified_pdf,
        modified_reader,
        field_info,
    )

    assert result["signed_revision_length"] == len(pdf_bytes)
    assert result["signed_revision_length"] < len(modified_pdf)

