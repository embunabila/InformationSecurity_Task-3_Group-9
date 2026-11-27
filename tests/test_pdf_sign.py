import io
import re
import unittest
from datetime import datetime, timedelta, timezone

from pypdf import PdfReader, PdfWriter
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    NameObject,
    NumberObject,
    TextStringObject,
)

from pdf_sign import (
    CONTENTS_SIZE,
    SIGNING_STATEMENT,
    prepare_pdf_for_signing,
)
from share_errors import AlreadySignedError, InvalidPdfError

SIGNER = "dummy_user"
SIGNING_TIME = datetime(2026, 11, 27, 9, 30, 0, tzinfo=timezone.utc)
PDF_DATE = "D:20261127093000+00'00'"


# --- dummy PDFs, built in the test (contract section 10) ---


def _to_bytes(writer):
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


def _blank_writer(pages=1):
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=200, height=200)
    return writer


def make_pdf(pages=1, title=None, header=None):
    writer = _blank_writer(pages)
    if title is not None:
        writer.add_metadata({"/Title": title})
    if header is not None:
        writer.pdf_header = header
    return _to_bytes(writer)


def make_pdf_with_form(signature_field=None, field_name="Medimo-Signature",
                       indirect=False, sig_flags=None, inherit_type=False):
    """PDF with an existing AcroForm and one existing field + widget.

    signature_field: None (a text field), "empty" (/Sig without /V),
    or "filled" (/Sig with /V).
    """
    writer = _blank_writer()
    page = writer.pages[0]

    field = DictionaryObject(
        {
            NameObject("/T"): TextStringObject(field_name),
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Widget"),
            NameObject("/Rect"): ArrayObject([NumberObject(0)] * 4),
        }
    )

    if signature_field is None:
        field[NameObject("/FT")] = NameObject("/Tx")
    else:
        field[NameObject("/FT")] = NameObject("/Sig")

    if signature_field == "filled":
        old_signature = writer._add_object(
            DictionaryObject({NameObject("/Type"): NameObject("/Sig")})
        )
        field[NameObject("/V")] = old_signature

    field_ref = writer._add_object(field)

    top_ref = field_ref
    if inherit_type:
        # /FT on the parent only, the kid holds /V (ISO 32000-1 12.7.3.1).
        kid = field_ref.get_object()
        del kid[NameObject("/FT")]
        del kid[NameObject("/T")]
        parent = DictionaryObject(
            {
                NameObject("/FT"): NameObject("/Sig"),
                NameObject("/T"): TextStringObject("Parent"),
                NameObject("/Kids"): ArrayObject([field_ref]),
            }
        )
        top_ref = writer._add_object(parent)
        kid[NameObject("/Parent")] = top_ref

    fields = ArrayObject([top_ref])
    annots = ArrayObject([field_ref])
    if indirect:
        fields = writer._add_object(fields)
        annots = writer._add_object(annots)

    page[NameObject("/Annots")] = annots

    acroform = DictionaryObject({NameObject("/Fields"): fields})
    if sig_flags is not None:
        acroform[NameObject("/SigFlags")] = NumberObject(sig_flags)
    if indirect:
        acroform = writer._add_object(acroform)

    writer.root_object[NameObject("/AcroForm")] = acroform
    return _to_bytes(writer)


def prepare(pdf, signer=SIGNER, signing_time=SIGNING_TIME):
    return prepare_pdf_for_signing(pdf, signer, signing_time)


def find_new_field(prepared):
    reader = PdfReader(io.BytesIO(prepared))
    fields = reader.trailer["/Root"]["/AcroForm"]["/Fields"]
    for field in fields:
        field = field.get_object()
        if field.get("/FT") == "/Sig" and "/V" in field:
            return reader, field
    raise AssertionError("New signature field not found.")


# --- tests ---


class ByteLayoutTests(unittest.TestCase):
    def setUp(self):
        self.original = make_pdf()
        self.prepared, self.byte_range = prepare(self.original)

    def test_starts_with_original_bytes(self):
        self.assertTrue(self.prepared.startswith(self.original))
        self.assertGreater(len(self.prepared), len(self.original))

    def test_byte_range_shape(self):
        zero, a, b, c = self.byte_range
        self.assertEqual(zero, 0)
        self.assertGreater(a, len(self.original))
        self.assertLess(a, b)
        # The second range reaches the end of the file.
        self.assertEqual(b + c, len(self.prepared))

    def test_gap_is_exactly_the_contents_placeholder(self):
        _, a, b, _ = self.byte_range
        self.assertEqual(self.prepared[a:a + 1], b"<")
        self.assertEqual(self.prepared[b - 1:b], b">")
        self.assertEqual(self.prepared[a + 1:b - 1], b"0" * (2 * CONTENTS_SIZE))

    def test_written_byte_range_matches_returned_value(self):
        match = re.search(
            rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]",
            self.prepared[len(self.original):],
        )
        self.assertIsNotNone(match)
        self.assertEqual([int(n) for n in match.groups()], self.byte_range)

    def test_byte_range_sits_in_the_signed_part(self):
        _, a, b, _ = self.byte_range
        position = self.prepared.index(b"/ByteRange", len(self.original))
        self.assertFalse(a <= position < b)

    def test_placeholders_appear_once_in_the_update(self):
        appended = self.prepared[len(self.original):]
        self.assertEqual(appended.count(b"0" * (2 * CONTENTS_SIZE)), 1)
        self.assertEqual(appended.count(b"/ByteRange"), 1)
        self.assertEqual(appended.count(b"/Contents"), 1)

    def test_signature_dict_is_not_in_an_object_stream(self):
        # The signature dictionary must be readable in the raw bytes.
        appended = self.prepared[len(self.original):]
        self.assertIn(b"/Type /Sig", appended)
        self.assertIn(b"/SubFilter /adbe.pkcs7.detached", appended)

    def test_output_is_bytes_and_readable(self):
        self.assertIsInstance(self.prepared, bytes)
        self.assertEqual(len(PdfReader(io.BytesIO(self.prepared)).pages), 1)


class SignatureStructureTests(unittest.TestCase):
    def setUp(self):
        self.prepared, _ = prepare(make_pdf())
        self.reader, self.field = find_new_field(self.prepared)
        self.signature = self.field["/V"].get_object()

    def test_signature_dictionary(self):
        self.assertEqual(self.signature["/Type"], "/Sig")
        self.assertEqual(self.signature["/Filter"], "/Adobe.PPKLite")
        self.assertEqual(self.signature["/SubFilter"], "/adbe.pkcs7.detached")
        # pypdf may decode an all-zero string as UTF-16 text, so compare
        # the raw bytes. (Verification reads the ByteRange gap, not this.)
        contents = self.signature["/Contents"].original_bytes
        self.assertEqual(contents, b"\x00" * CONTENTS_SIZE)

    def test_signature_text_entries(self):
        self.assertEqual(self.signature["/Reason"], SIGNING_STATEMENT)
        self.assertEqual(self.signature["/Name"], SIGNER)
        self.assertEqual(self.signature["/M"], PDF_DATE)

    def test_signing_statement_matches_contract(self):
        self.assertEqual(
            SIGNING_STATEMENT,
            "Saya menyatakan dokumen ini saya serahkan dan isinya tidak "
            "diubah setelah saya tanda tangani.",
        )

    def test_field_and_widget(self):
        page = self.reader.pages[0]
        self.assertEqual(self.field["/FT"], "/Sig")
        self.assertEqual(self.field["/T"], "Medimo-Signature")
        self.assertEqual(self.field["/Subtype"], "/Widget")
        self.assertEqual(self.field["/Type"], "/Annot")
        self.assertEqual([float(n) for n in self.field["/Rect"]], [0, 0, 0, 0])
        self.assertEqual(self.field["/F"], 132)
        self.assertEqual(
            self.field.raw_get("/P").idnum, page.indirect_reference.idnum
        )

    def test_widget_is_on_page_one(self):
        annots = self.reader.pages[0]["/Annots"]
        ids = [ref.idnum for ref in annots]
        self.assertIn(self.field.indirect_reference.idnum, ids)

    def test_acroform_flags(self):
        acroform = self.reader.trailer["/Root"]["/AcroForm"]
        self.assertEqual(acroform["/SigFlags"], 3)

    def test_widget_only_on_first_page(self):
        prepared, _ = prepare(make_pdf(pages=3))
        reader = PdfReader(io.BytesIO(prepared))
        self.assertIn("/Annots", reader.pages[0])
        self.assertNotIn("/Annots", reader.pages[1])
        self.assertNotIn("/Annots", reader.pages[2])

    def test_name_with_pdf_syntax_is_escaped(self):
        # A name full of PDF delimiters must stay one string value.
        name = "x) /Evil (y\\"
        prepared, _ = prepare(make_pdf(), signer=name)
        _, field = find_new_field(prepared)
        signature = field["/V"].get_object()
        self.assertEqual(signature["/Name"], name)
        self.assertNotIn("/Evil", signature)


class ExistingFormTests(unittest.TestCase):
    def test_existing_fields_and_annots_are_kept(self):
        prepared, _ = prepare(make_pdf_with_form(field_name="Old-Field"))
        reader = PdfReader(io.BytesIO(prepared))

        fields = reader.trailer["/Root"]["/AcroForm"]["/Fields"]
        names = [str(f.get_object()["/T"]) for f in fields]
        self.assertEqual(names, ["Old-Field", "Medimo-Signature"])
        self.assertEqual(len(reader.pages[0]["/Annots"]), 2)

    def test_indirect_arrays_are_appended_not_replaced(self):
        original = make_pdf_with_form(field_name="Old-Field", indirect=True)
        prepared, _ = prepare(original)
        reader = PdfReader(io.BytesIO(prepared))

        root = reader.trailer["/Root"]
        # Still indirect references after the update.
        self.assertTrue(hasattr(root.raw_get("/AcroForm"), "idnum"))
        acroform = root["/AcroForm"]
        self.assertTrue(hasattr(acroform.raw_get("/Fields"), "idnum"))
        self.assertTrue(hasattr(reader.pages[0].raw_get("/Annots"), "idnum"))

        self.assertEqual(len(acroform["/Fields"]), 2)
        self.assertEqual(len(reader.pages[0]["/Annots"]), 2)

    def test_existing_sig_flags_are_or_ed(self):
        prepared, _ = prepare(make_pdf_with_form(field_name="Old", sig_flags=4))
        reader = PdfReader(io.BytesIO(prepared))
        self.assertEqual(reader.trailer["/Root"]["/AcroForm"]["/SigFlags"], 7)

    def test_empty_signature_field_is_allowed_and_name_gets_number(self):
        original = make_pdf_with_form(signature_field="empty")
        prepared, _ = prepare(original)
        _, field = find_new_field(prepared)
        self.assertEqual(field["/T"], "Medimo-Signature-2")

    def test_filled_signature_field_is_rejected(self):
        with self.assertRaises(AlreadySignedError):
            prepare(make_pdf_with_form(signature_field="filled"))

    def test_filled_signature_with_inherited_type_is_rejected(self):
        original = make_pdf_with_form(signature_field="filled", inherit_type=True)
        with self.assertRaises(AlreadySignedError):
            prepare(original)

    def test_cannot_prepare_twice(self):
        prepared, _ = prepare(make_pdf())
        with self.assertRaises(AlreadySignedError):
            prepare(prepared)


class MetadataAndVersionTests(unittest.TestCase):
    def test_mod_date_updated_when_info_exists(self):
        original = make_pdf(title="Dummy")
        prepared, _ = prepare(original)
        appended = prepared[len(original):]

        self.assertIn(b"/Info", appended)
        metadata = PdfReader(io.BytesIO(prepared)).metadata
        self.assertEqual(metadata["/ModDate"], PDF_DATE)
        self.assertEqual(metadata["/Title"], "Dummy")

    def test_no_info_created_when_missing(self):
        writer = _blank_writer()
        writer._info = None
        original = _to_bytes(writer)
        self.assertNotIn(b"/Info", original)

        prepared, _ = prepare(original)
        self.assertNotIn(b"/Info", prepared)
        self.assertNotIn(b"/ModDate", prepared)

    def test_version_raised_for_old_header(self):
        original = make_pdf(header="%PDF-1.3")
        prepared, _ = prepare(original)
        root = PdfReader(io.BytesIO(prepared)).trailer["/Root"]
        self.assertEqual(root["/Version"], "/1.5")

    def test_version_not_added_for_new_header(self):
        original = make_pdf(header="%PDF-1.7")
        prepared, _ = prepare(original)
        root = PdfReader(io.BytesIO(prepared)).trailer["/Root"]
        self.assertNotIn("/Version", root)

    def test_existing_catalog_version_is_kept(self):
        writer = _blank_writer()
        writer.pdf_header = "%PDF-1.3"
        writer.root_object[NameObject("/Version")] = NameObject("/1.7")
        prepared, _ = prepare(_to_bytes(writer))
        root = PdfReader(io.BytesIO(prepared)).trailer["/Root"]
        self.assertEqual(root["/Version"], "/1.7")


class RejectedInputTests(unittest.TestCase):
    def test_encrypted_pdf(self):
        writer = _blank_writer()
        writer.encrypt("dummy-password", algorithm="RC4-128")
        with self.assertRaises(InvalidPdfError):
            prepare(_to_bytes(writer))

    def test_damaged_pdf(self):
        for data in (b"%PDF-1.4 garbage", b"not a pdf", b""):
            with self.subTest(data=data):
                with self.assertRaises(InvalidPdfError):
                    prepare(data)

    def test_pdf_without_pages(self):
        with self.assertRaises(InvalidPdfError):
            prepare(_to_bytes(PdfWriter()))

    def test_pdf_bytes_must_be_bytes(self):
        with self.assertRaises(ValueError):
            prepare(bytearray(make_pdf()))

    def test_signing_time_rules(self):
        bad_times = {
            "naive": datetime(2026, 11, 27, 9, 30, 0),
            "not utc": datetime(
                2026, 11, 27, 16, 30, 0, tzinfo=timezone(timedelta(hours=7))
            ),
            "microseconds": SIGNING_TIME.replace(microsecond=1),
            "not datetime": "2026-11-27T09:30:00Z",
        }
        for label, value in bad_times.items():
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    prepare(make_pdf(), signing_time=value)

    def test_signer_name_rules(self):
        for value in ("", "   ", None, 7):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    prepare(make_pdf(), signer=value)


if __name__ == "__main__":
    unittest.main()