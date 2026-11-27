import hashlib
import io
import os
import re
import unittest
from pathlib import Path
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
    byte_range_digest,
    embed_signature,
    prepare_pdf_for_signing,
)
from share_errors import AlreadySignedError, InvalidPdfError

SIGNER = "dummy_user"
SIGNING_TIME = datetime(2026, 11, 27, 9, 30, 0, tzinfo=timezone.utc)
PDF_DATE = "D:20261127093000+00'00'"

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE_FILES = {
    "01_Pemeriksaan_Lab_Word.pdf": {"xref": "hybrid", "version_added": False},
    "02_Surat_Chrome.pdf": {"xref": "table", "version_added": True},
}
TEAM_NAMES = ("della", "embun", "nayla", "nuha")


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


class ByteRangeDigestTests(unittest.TestCase):
    def setUp(self):
        self.prepared, self.byte_range = prepare(make_pdf())

    def test_matches_manual_sha256(self):
        _, a, b, c = self.byte_range
        expected = hashlib.sha256(
            self.prepared[0:a] + self.prepared[b:b + c]
        ).digest()
        self.assertEqual(byte_range_digest(self.prepared, self.byte_range), expected)

    def test_digest_is_32_bytes(self):
        digest = byte_range_digest(self.prepared, self.byte_range)
        self.assertIsInstance(digest, bytes)
        self.assertEqual(len(digest), 32)

    def test_byte_outside_gap_changes_digest(self):
        _, a, b, c = self.byte_range
        before = byte_range_digest(self.prepared, self.byte_range)
        for position in (0, a - 1, b, b + c - 1):
            with self.subTest(position=position):
                changed = bytearray(self.prepared)
                changed[position] ^= 0x01
                self.assertNotEqual(
                    byte_range_digest(bytes(changed), self.byte_range), before
                )

    def test_byte_inside_gap_does_not_change_digest(self):
        _, a, b, _ = self.byte_range
        before = byte_range_digest(self.prepared, self.byte_range)
        changed = bytearray(self.prepared)
        changed[a + 1:b - 1] = b"F" * (b - a - 2)
        self.assertEqual(byte_range_digest(bytes(changed), self.byte_range), before)

    def test_extra_bytes_after_range_are_allowed(self):
        before = byte_range_digest(self.prepared, self.byte_range)
        longer = self.prepared + b"\n% appended later\n"
        self.assertEqual(byte_range_digest(longer, self.byte_range), before)

    def test_tuple_is_accepted(self):
        self.assertEqual(
            byte_range_digest(self.prepared, tuple(self.byte_range)),
            byte_range_digest(self.prepared, self.byte_range),
        )

    def test_bad_byte_range_is_rejected(self):
        _, a, b, c = self.byte_range
        bad = {
            "three numbers": [0, a, b],
            "five numbers": [0, a, b, c, 0],
            "negative": [0, a, b, -1],
            "not starting at zero": [1, a, b, c],
            "empty gap": [0, a, a, c],
            "gap backwards": [0, b, a, c],
            "past the end": [0, a, b, c + 1],
            "bool": [0, a, b, True],
            "string": [0, a, b, str(c)],
            "float": [0, a, b, float(c)],
            "not a list": "0 1 2 3",
        }
        for label, value in bad.items():
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    byte_range_digest(self.prepared, value)

    def test_pdf_must_be_bytes(self):
        with self.assertRaises(ValueError):
            byte_range_digest(bytearray(self.prepared), self.byte_range)


class EmbedSignatureTests(unittest.TestCase):
    def setUp(self):
        self.prepared, self.byte_range = prepare(make_pdf())
        self.cms = os.urandom(2000)

    def test_length_and_outside_bytes_unchanged(self):
        signed = embed_signature(self.prepared, self.byte_range, self.cms)
        _, a, b, c = self.byte_range
        self.assertEqual(len(signed), len(self.prepared))
        self.assertEqual(signed[:a + 1], self.prepared[:a + 1])
        self.assertEqual(signed[b - 1:], self.prepared[b - 1:])

    def test_gap_holds_uppercase_hex_then_zeros(self):
        signed = embed_signature(self.prepared, self.byte_range, self.cms)
        _, a, b, _ = self.byte_range
        gap = signed[a + 1:b - 1]
        cms_hex = self.cms.hex().upper().encode("ascii")

        self.assertEqual(len(gap), 2 * CONTENTS_SIZE)
        self.assertTrue(gap.startswith(cms_hex))
        self.assertEqual(gap[len(cms_hex):], b"0" * (len(gap) - len(cms_hex)))
        self.assertEqual(gap, gap.upper())

    def test_gap_decodes_to_cms_plus_zero_padding(self):
        signed = embed_signature(self.prepared, self.byte_range, self.cms)
        _, a, b, _ = self.byte_range
        decoded = bytes.fromhex(signed[a + 1:b - 1].decode("ascii"))
        self.assertEqual(len(decoded), CONTENTS_SIZE)
        self.assertEqual(decoded[:len(self.cms)], self.cms)
        self.assertEqual(decoded[len(self.cms):], b"\x00" * (CONTENTS_SIZE - len(self.cms)))

    def test_digest_is_the_same_before_and_after(self):
        before = byte_range_digest(self.prepared, self.byte_range)
        signed = embed_signature(self.prepared, self.byte_range, self.cms)
        self.assertEqual(byte_range_digest(signed, self.byte_range), before)

    def test_result_is_still_readable(self):
        signed = embed_signature(self.prepared, self.byte_range, self.cms)
        self.assertEqual(len(PdfReader(io.BytesIO(signed)).pages), 1)

    def test_cms_size_limits(self):
        exact = os.urandom(CONTENTS_SIZE)
        signed = embed_signature(self.prepared, self.byte_range, exact)
        _, a, b, _ = self.byte_range
        self.assertEqual(signed[a + 1:b - 1], exact.hex().upper().encode("ascii"))

        for label, value in (
            ("too big", os.urandom(CONTENTS_SIZE + 1)),
            ("empty", b""),
            ("not bytes", bytearray(self.cms)),
        ):
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    embed_signature(self.prepared, self.byte_range, value)

    def test_cannot_embed_twice(self):
        signed = embed_signature(self.prepared, self.byte_range, self.cms)
        with self.assertRaises(ValueError):
            embed_signature(signed, self.byte_range, os.urandom(100))

    def test_byte_range_must_point_to_placeholder(self):
        _, a, b, c = self.byte_range
        for label, value in (
            ("shifted", [0, a + 1, b + 1, c - 1]),
            ("too short", [0, a, b - 2, c + 2]),
            ("start of file", [0, 1, b, c]),
        ):
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    embed_signature(self.prepared, value, self.cms)

    def test_bad_byte_range_is_rejected(self):
        with self.assertRaises(ValueError):
            embed_signature(self.prepared, [0, 1, 2], self.cms)

    def test_prepared_pdf_must_be_bytes(self):
        with self.assertRaises(ValueError):
            embed_signature(bytearray(self.prepared), self.byte_range, self.cms)


def xref_kind(pdf):
    has_table = re.search(rb"(?m)^xref\s", pdf) is not None
    has_stream = re.search(rb"/Type\s*/XRef\b", pdf) is not None
    if has_table and b"/XRefStm" in pdf:
        return "hybrid"
    if has_table and not has_stream:
        return "table"
    if has_stream and not has_table:
        return "stream"
    return "mixed"


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.fixtures = [
            (name, expected, (FIXTURES / name).read_bytes())
            for name, expected in FIXTURE_FILES.items()
        ]

    def test_fixture_xref_structure(self):
        for name, expected, pdf in self.fixtures:
            with self.subTest(fixture=name):
                self.assertEqual(xref_kind(pdf), expected["xref"])

    def test_prepare_byte_layout(self):
        for name, _, pdf in self.fixtures:
            with self.subTest(fixture=name):
                prepared, byte_range = prepare(pdf)
                _, a, b, c = byte_range
                self.assertTrue(prepared.startswith(pdf))
                self.assertEqual(b + c, len(prepared))
                self.assertEqual(
                    prepared[a:b], b"<" + b"0" * (2 * CONTENTS_SIZE) + b">"
                )

    def test_prepare_structure(self):
        for name, _, pdf in self.fixtures:
            with self.subTest(fixture=name):
                prepared, _ = prepare(pdf)
                reader, field = find_new_field(prepared)
                signature = field["/V"].get_object()
                acroform = reader.trailer["/Root"]["/AcroForm"]
                annot_ids = [ref.idnum for ref in reader.pages[0]["/Annots"]]

                self.assertEqual(field["/T"], "Medimo-Signature")
                self.assertEqual(signature["/Reason"], SIGNING_STATEMENT)
                self.assertEqual(signature["/Name"], SIGNER)
                self.assertEqual(acroform["/SigFlags"], 3)
                self.assertIn(field.indirect_reference.idnum, annot_ids)
                self.assertEqual(
                    len(reader.pages), len(PdfReader(io.BytesIO(pdf)).pages)
                )

    def test_version_only_added_below_1_5(self):
        for name, expected, pdf in self.fixtures:
            with self.subTest(fixture=name):
                prepared, _ = prepare(pdf)
                root = PdfReader(io.BytesIO(prepared)).trailer["/Root"]
                if expected["version_added"]:
                    self.assertEqual(root["/Version"], "/1.5")
                else:
                    self.assertNotIn("/Version", root)

    def test_mod_date_updated_and_info_kept(self):
        for name, _, pdf in self.fixtures:
            with self.subTest(fixture=name):
                before = PdfReader(io.BytesIO(pdf)).metadata
                prepared, _ = prepare(pdf)
                after = PdfReader(io.BytesIO(prepared)).metadata

                self.assertEqual(after["/ModDate"], PDF_DATE)
                for key in before:
                    if key != "/ModDate":
                        self.assertEqual(after[key], before[key])

    def test_prepare_then_embed_keeps_digest(self):
        for name, _, pdf in self.fixtures:
            with self.subTest(fixture=name):
                prepared, byte_range = prepare(pdf)
                before = byte_range_digest(prepared, byte_range)
                signed = embed_signature(prepared, byte_range, os.urandom(2000))

                self.assertEqual(byte_range_digest(signed, byte_range), before)
                self.assertEqual(len(PdfReader(io.BytesIO(signed)).pages), 1)

    def test_fixture_metadata_has_no_real_names(self):
        for name, _, pdf in self.fixtures:
            with self.subTest(fixture=name):
                reader = PdfReader(io.BytesIO(pdf))
                info = reader.metadata or {}
                self.assertNotIn("/Author", info)

                values = [str(value) for value in info.values()]
                xmp = reader.xmp_metadata
                if xmp is not None:
                    self.assertFalse(xmp.dc_creator)
                    values += [str(v) for v in (xmp.dc_title or {}).values()]

                text = " ".join(values).lower()
                for team_name in TEAM_NAMES:
                    self.assertNotIn(team_name, text)

if __name__ == "__main__":
    unittest.main()