"""Prepare, hash, and embed PDF digital signatures

The signature is added as an incremental update (ISO 32000-1 7.5.6), so
the original PDF bytes stay untouched at the start of the signed file.
The hash covers every byte except the /Contents hex string, including
its "<" and ">" delimiters (ISO 32000-1 12.8.1).
"""

import io
import re
from datetime import datetime, timedelta

from pypdf import PdfReader, PdfWriter
from pypdf.errors import PyPdfError
from pypdf.generic import (
    ArrayObject,
    ByteStringObject,
    DictionaryObject,
    NameObject,
    NumberObject,
    TextStringObject,
)

from share_errors import AlreadySignedError, InvalidPdfError


SIGNING_STATEMENT = (
    "Saya menyatakan dokumen ini saya serahkan dan isinya tidak diubah "
    "setelah saya tanda tangani."
)

# Space reserved for the CMS SignedData inside /Contents (contract section 4).
CONTENTS_SIZE = 8192

# Fixed-width stand-in for the three unknown ByteRange numbers. Ten digits
# cover any file Medimo accepts (25 MiB), so the real numbers always fit.
BYTE_RANGE_PLACEHOLDER = 9_999_999_999

FIELD_NAME = "Medimo-Signature"
MAX_FIELD_NAME_ATTEMPTS = 100

# /F 132 = Print (4) + Locked (128), ISO 32000-1 12.5.3.
WIDGET_FLAGS = 132

# SignaturesExist (1) + AppendOnly (2), ISO 32000-1 12.7.2.
SIG_FLAGS = 3

# Cross-reference streams need PDF 1.5 (ISO 32000-1 7.5.8), and pypdf
# always writes the incremental update with one.
XREF_STREAM_VERSION = (1, 5)

# Guards against reference loops while walking the field tree.
MAX_FIELD_DEPTH = 32

# Errors pypdf may raise on a damaged file.
_PDF_READ_ERRORS = (
    PyPdfError,
    ValueError,
    TypeError,
    KeyError,
    IndexError,
    AttributeError,
    RecursionError,
)


def _check_signing_time(signing_time):
    if not isinstance(signing_time, datetime):
        raise ValueError("signing_time must be a datetime.")

    if signing_time.tzinfo is None:
        raise ValueError("signing_time must be timezone-aware.")

    if signing_time.utcoffset() != timedelta(0):
        raise ValueError("signing_time must be in UTC.")

    if signing_time.microsecond != 0:
        raise ValueError("signing_time must be truncated to whole seconds.")


def _check_signer_name(signer_name):
    if not isinstance(signer_name, str) or not signer_name.strip():
        raise ValueError("signer_name must be a non-empty string.")


def _pdf_date(signing_time):
    """Format a UTC datetime as a PDF date string (ISO 32000-1 7.9.4)."""
    return signing_time.strftime("D:%Y%m%d%H%M%S+00'00'")


def _parse_version(value):
    """Return (major, minor) from "1.7", "/1.7" or "%PDF-1.7", else None."""
    match = re.search(r"(\d+)\.(\d+)", str(value))
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


def _open_reader(pdf_bytes):
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))

        if reader.is_encrypted:
            raise InvalidPdfError("Encrypted PDFs are not supported.")

        if len(reader.pages) == 0:
            raise InvalidPdfError("The PDF has no pages.")
    except InvalidPdfError:
        raise
    except _PDF_READ_ERRORS:
        raise InvalidPdfError("The PDF cannot be read.") from None

    return reader


def _top_level_fields(acroform):
    if acroform is None:
        return []

    fields = acroform.get("/Fields")
    if fields is None:
        return []

    fields = fields.get_object()
    if not isinstance(fields, ArrayObject):
        raise InvalidPdfError("The PDF form is damaged.")

    return [field.get_object() for field in fields]


def _has_filled_signature(fields):
    """True if any field (or descendant) is /FT /Sig with a /V entry.

    Deliberately minimal: it only answers "may we add a signature?".
    Reading signatures for verification is extract_signatures (Nayla).
    """
    seen = set()
    stack = [(field, None, 0) for field in fields]

    while stack:
        field, inherited_type, depth = stack.pop()

        if not isinstance(field, DictionaryObject):
            continue

        if depth > MAX_FIELD_DEPTH:
            raise InvalidPdfError("The PDF form is damaged.")

        reference = field.indirect_reference
        if reference is not None:
            key = (reference.idnum, reference.generation)
            if key in seen:
                continue
            seen.add(key)

        # /FT is inheritable from the parent field (ISO 32000-1 12.7.3.1).
        field_type = field.get("/FT", inherited_type)

        if field_type == "/Sig" and field.get("/V") is not None:
            return True

        kids = field.get("/Kids")
        if kids is not None:
            kids = kids.get_object()
            if isinstance(kids, ArrayObject):
                for kid in kids:
                    stack.append((kid.get_object(), field_type, depth + 1))

    return False


def _choose_field_name(fields):
    taken = {str(field.get("/T")) for field in fields if "/T" in field}

    if FIELD_NAME not in taken:
        return FIELD_NAME

    for number in range(2, MAX_FIELD_NAME_ATTEMPTS + 1):
        name = f"{FIELD_NAME}-{number}"
        if name not in taken:
            return name

    raise InvalidPdfError("No free signature field name.")


def _serialize(pdf_object):
    buffer = io.BytesIO()
    pdf_object.write_to_stream(buffer)
    return buffer.getvalue()


def _byte_range_placeholder():
    return ArrayObject(
        [
            NumberObject(0),
            NumberObject(BYTE_RANGE_PLACEHOLDER),
            NumberObject(BYTE_RANGE_PLACEHOLDER),
            NumberObject(BYTE_RANGE_PLACEHOLDER),
        ]
    )


def _contents_placeholder():
    return ByteStringObject(b"\x00" * CONTENTS_SIZE)


def _add_signature_objects(writer, reader, signer_name, signing_time):
    root = writer.root_object
    page = writer.pages[0]

    acroform = root.get("/AcroForm")
    if acroform is not None:
        acroform = acroform.get_object()
        if not isinstance(acroform, DictionaryObject):
            raise InvalidPdfError("The PDF form is damaged.")

    fields = _top_level_fields(acroform)

    if _has_filled_signature(fields):
        raise AlreadySignedError("The PDF already has a signature.")

    field_name = _choose_field_name(fields)
    pdf_date = _pdf_date(signing_time)

    # Text goes through pypdf string objects, never hand-built syntax,
    # so a name cannot inject PDF syntax (contract section 4).
    signature = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Sig"),
            NameObject("/Filter"): NameObject("/Adobe.PPKLite"),
            NameObject("/SubFilter"): NameObject("/adbe.pkcs7.detached"),
            NameObject("/ByteRange"): _byte_range_placeholder(),
            NameObject("/Contents"): _contents_placeholder(),
            NameObject("/M"): TextStringObject(pdf_date),
            NameObject("/Name"): TextStringObject(signer_name),
            NameObject("/Reason"): TextStringObject(SIGNING_STATEMENT),
        }
    )
    # pypdf has no public "add object" call; _add_object is private API.
    # The pypdf version is pinned (<7) and the tests below catch changes.
    signature_ref = writer._add_object(signature)

    widget = DictionaryObject(
        {
            NameObject("/FT"): NameObject("/Sig"),
            NameObject("/T"): TextStringObject(field_name),
            NameObject("/V"): signature_ref,
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Widget"),
            NameObject("/Rect"): ArrayObject([NumberObject(0)] * 4),
            NameObject("/F"): NumberObject(WIDGET_FLAGS),
            NameObject("/P"): page.indirect_reference,
        }
    )
    widget_ref = writer._add_object(widget)

    # Append to existing arrays (direct or indirect); never replace them.
    annots = page.get("/Annots")
    if annots is None:
        page[NameObject("/Annots")] = ArrayObject([widget_ref])
    else:
        annots = annots.get_object()
        if not isinstance(annots, ArrayObject):
            raise InvalidPdfError("The PDF page annotations are damaged.")
        annots.append(widget_ref)

    if acroform is None:
        root[NameObject("/AcroForm")] = DictionaryObject(
            {
                NameObject("/Fields"): ArrayObject([widget_ref]),
                NameObject("/SigFlags"): NumberObject(SIG_FLAGS),
            }
        )
    else:
        acro_fields = acroform.get("/Fields")
        if acro_fields is None:
            acroform[NameObject("/Fields")] = ArrayObject([widget_ref])
        else:
            acro_fields.get_object().append(widget_ref)

        old_flags = acroform.get("/SigFlags")
        old_flags = old_flags.get_object() if old_flags is not None else 0
        if not isinstance(old_flags, int):
            raise InvalidPdfError("The PDF form is damaged.")
        acroform[NameObject("/SigFlags")] = NumberObject(
            int(old_flags) | SIG_FLAGS
        )

    # Keep /Info in the new trailer (ISO 32000-1 7.5.6) by updating
    # /ModDate, but only if the original PDF has /Info at all.
    if "/Info" in reader.trailer:
        writer.add_metadata({"/ModDate": pdf_date})

    # The update uses a cross-reference stream (PDF 1.5). Raise the
    # version through the catalog (ISO 32000-1 7.2.2) only when needed.
    header_version = _parse_version(reader.pdf_header)
    catalog_version = None
    if "/Version" in root:
        catalog_version = _parse_version(root["/Version"])

    needs_version = (
        header_version is None or header_version < XREF_STREAM_VERSION
    ) and (catalog_version is None or catalog_version < XREF_STREAM_VERSION)

    if needs_version:
        root[NameObject("/Version")] = NameObject("/1.5")


def _locate_once(data, needle, label):
    first = data.find(needle)
    if first < 0 or data.find(needle, first + 1) >= 0:
        # Missing means the object went into a compressed object stream;
        # twice means the placeholder is ambiguous. Either is a bug.
        raise RuntimeError(f"{label} placeholder must appear exactly once.")
    return first


def prepare_pdf_for_signing(pdf_bytes, signer_name, signing_time):
    """Append an empty signature field to a PDF as an incremental update.

    Returns (prepared_pdf, byte_range). byte_range is [0, a, b, c]:
    the signed bytes are prepared_pdf[0:a] + prepared_pdf[b:b + c], and
    prepared_pdf[a:b] is the /Contents hex string "<00...00>".
    """
    if not isinstance(pdf_bytes, bytes):
        raise ValueError("pdf_bytes must be bytes.")

    _check_signer_name(signer_name)
    _check_signing_time(signing_time)

    reader = _open_reader(pdf_bytes)

    try:
        writer = PdfWriter(reader, incremental=True)
        _add_signature_objects(writer, reader, signer_name, signing_time)

        output = io.BytesIO()
        writer.write(output)
    except (InvalidPdfError, AlreadySignedError):
        raise
    except _PDF_READ_ERRORS:
        raise InvalidPdfError("The PDF cannot be read.") from None

    prepared = output.getvalue()

    if not prepared.startswith(pdf_bytes):
        raise RuntimeError("Incremental update changed the original bytes.")

    original_length = len(pdf_bytes)
    appended = prepared[original_length:]

    contents_needle = _serialize(_contents_placeholder())
    byte_range_needle = _serialize(_byte_range_placeholder())

    contents_at = original_length + _locate_once(
        appended, contents_needle, "/Contents"
    )
    byte_range_at = original_length + _locate_once(
        appended, byte_range_needle, "/ByteRange"
    )

    a = contents_at
    b = contents_at + len(contents_needle)
    c = len(prepared) - b
    byte_range = [0, a, b, c]

    # Real numbers, padded with spaces so the file length does not change.
    filled = f"[ 0 {a} {b} {c}".encode("ascii")
    filled = filled.ljust(len(byte_range_needle) - 1) + b"]"

    if len(filled) != len(byte_range_needle):
        raise RuntimeError("ByteRange does not fit its placeholder.")

    prepared = (
        prepared[:byte_range_at]
        + filled
        + prepared[byte_range_at + len(byte_range_needle):]
    )

    return prepared, byte_range