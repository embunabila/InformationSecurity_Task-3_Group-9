"""PDF signature preparation, hashing, and embedding."""

import hmac
import io
import re
from datetime import datetime, timedelta, timezone

from Crypto.Hash import SHA256
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

from share_errors import AlreadySignedError, InvalidPdfError, KeyExpiredError


SIGNING_STATEMENT = (
    "Saya menyatakan dokumen ini saya serahkan dan isinya tidak diubah "
    "setelah saya tanda tangani."
)

CONTENTS_SIZE = 8192
BYTE_RANGE_PLACEHOLDER = 9_999_999_999
FIELD_NAME = "Medimo-Signature"
MAX_FIELD_NAME_ATTEMPTS = 100
WIDGET_FLAGS = 132  # Print + Locked
SIG_FLAGS = 3  # SignaturesExist + AppendOnly
XREF_STREAM_VERSION = (1, 5)
MAX_FIELD_DEPTH = 32

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
    """Return a PDF date string (ISO 32000-1 7.9.4)."""
    return signing_time.strftime("D:%Y%m%d%H%M%S+00'00'")


def _parse_version(value):
    """Return (major, minor) parsed from a version string, or None."""
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
    """Return True if any field or descendant is a /Sig field with /V."""
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
    # _add_object is private pypdf API (pinned <7).
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

    if "/Info" in reader.trailer:
        writer.add_metadata({"/ModDate": pdf_date})

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
        raise RuntimeError(f"{label} placeholder must appear exactly once.")
    return first


def prepare_pdf_for_signing(pdf_bytes, signer_name, signing_time):
    """Add an empty signature field as an incremental update.

    Returns (prepared_pdf, [0, a, b, c]).
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


def _check_byte_range(byte_range, data_length):
    """Validate the shape and bounds of [0, a, b, c]."""
    if not isinstance(byte_range, (list, tuple)) or len(byte_range) != 4:
        raise ValueError("byte_range must be four integers.")

    for number in byte_range:
        if isinstance(number, bool) or not isinstance(number, int):
            raise ValueError("byte_range must be four integers.")
        if number < 0:
            raise ValueError("byte_range numbers must not be negative.")

    zero, a, b, c = byte_range

    if zero != 0:
        raise ValueError("byte_range must start at 0.")

    if a >= b:
        raise ValueError("byte_range gap must not be empty.")

    if b + c > data_length:
        raise ValueError("byte_range goes past the end of the PDF.")

    return a, b, c


def byte_range_digest(pdf_bytes, byte_range):
    """Return SHA-256 of pdf_bytes[0:a] + pdf_bytes[b:b + c]."""
    if not isinstance(pdf_bytes, bytes):
        raise ValueError("pdf_bytes must be bytes.")

    a, b, c = _check_byte_range(byte_range, len(pdf_bytes))

    hasher = SHA256.new()
    hasher.update(pdf_bytes[0:a])
    hasher.update(pdf_bytes[b:b + c])
    return hasher.digest()


def _contents_gap():
    """Return the placeholder bytes <00...00>."""
    return _serialize(_contents_placeholder())


def embed_signature(prepared_pdf, byte_range, cms_der):
    """Write cms_der as uppercase hex into the /Contents placeholder."""
    if not isinstance(prepared_pdf, bytes):
        raise ValueError("prepared_pdf must be bytes.")

    if not isinstance(cms_der, bytes):
        raise ValueError("cms_der must be bytes.")

    if not cms_der:
        raise ValueError("cms_der must not be empty.")

    if len(cms_der) > CONTENTS_SIZE:
        raise ValueError("cms_der does not fit in /Contents.")

    a, b, _ = _check_byte_range(byte_range, len(prepared_pdf))

    if prepared_pdf[a:b] != _contents_gap():
        raise ValueError("byte_range does not point to an empty /Contents.")

    hex_width = 2 * CONTENTS_SIZE
    filled = cms_der.hex().upper().encode("ascii").ljust(hex_width, b"0")

    signed_pdf = prepared_pdf[:a + 1] + filled + prepared_pdf[b - 1:]

    same_digest = hmac.compare_digest(
        byte_range_digest(signed_pdf, byte_range),
        byte_range_digest(prepared_pdf, byte_range),
    )
    if len(signed_pdf) != len(prepared_pdf) or not same_digest:
        raise RuntimeError("Embedding changed bytes outside /Contents.")

    return signed_pdf


# --- signing ---


def _utc_now():
    return datetime.now(timezone.utc)


def _parse_expires_at(value):
    try:
        expires_at = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        raise ValueError("Stored expires_at is not a valid timestamp.") from None

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    return expires_at.astimezone(timezone.utc)


def sign_pdf(pdf_bytes, user_id, password):
    """Sign a PDF with the user's signing key and return the signed PDF."""
    # Imported here so this module still loads before Della's modules exist,
    # the same pattern as grant_routes.py.
    from cms import build_cms_signed_data
    from db import get_user_by_id
    from signing_keys import get_signing_key, unlock_signing_key

    signing_key = get_signing_key(user_id)
    if signing_key is None:
        raise ValueError("The user has no signing key.")

    user = get_user_by_id(user_id)
    if user is None:
        raise ValueError("The user does not exist.")

    now = _utc_now().replace(microsecond=0)

    if now > _parse_expires_at(signing_key["expires_at"]):
        raise KeyExpiredError("The signing key has expired.")

    private_key = unlock_signing_key(user_id, password)

    prepared, byte_range = prepare_pdf_for_signing(
        pdf_bytes, user["username"], now
    )
    digest = byte_range_digest(prepared, byte_range)
    cms_der = build_cms_signed_data(
        digest, signing_key["certificate_der"], private_key, now
    )

    return embed_signature(prepared, byte_range, cms_der)