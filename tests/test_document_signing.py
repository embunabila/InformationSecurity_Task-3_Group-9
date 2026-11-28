
import io
import unittest
from datetime import datetime, timezone

from pypdf import PdfWriter

from document_signing import validate_pdf, MAX_PDF_SIZE
from pdf_sign import prepare_pdf_for_signing
from share_errors import InvalidPdfError, AlreadySignedError


def make_pdf():
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)

    buffer = io.BytesIO()
    writer.write(buffer)

    return buffer.getvalue()


class TestValidatePdf(unittest.TestCase):

    def test_reject_non_bytes(self):
        with self.assertRaises(InvalidPdfError):
            validate_pdf("not bytes")

    def test_reject_empty_file(self):
        with self.assertRaises(InvalidPdfError):
            validate_pdf(b"")

    def test_reject_non_pdf(self):
        with self.assertRaises(InvalidPdfError):
            validate_pdf(b"This is not a PDF file")

    def test_reject_invalid_pdf(self):
        with self.assertRaises(InvalidPdfError):
            validate_pdf(b"%PDF-invalid")

    def test_accept_valid_pdf(self):
        pdf_bytes = make_pdf()

        validate_pdf(pdf_bytes)

    def test_reject_encrypted_pdf(self):
        writer = PdfWriter()
        writer.add_blank_page(width=200, height=200)
        writer.encrypt("secret")

        buffer = io.BytesIO()
        writer.write(buffer)

        with self.assertRaises(InvalidPdfError):
            validate_pdf(buffer.getvalue())

    def test_reject_oversized_pdf(self):
        oversized_pdf = b"%PDF-" + b"A" * MAX_PDF_SIZE

        with self.assertRaises(InvalidPdfError):
            validate_pdf(oversized_pdf)

    def test_reject_already_signed_pdf(self):
        original_pdf = make_pdf()

        signing_time = datetime(
            2026, 11, 28, 9, 0, 0,
            tzinfo=timezone.utc
        )

        signed_pdf, _ = prepare_pdf_for_signing(
            original_pdf,
            "Medimo Test User",
            signing_time
        )

        with self.assertRaises(AlreadySignedError):
            validate_pdf(signed_pdf)


if __name__ == "__main__":
    unittest.main()
