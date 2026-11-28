
from io import BytesIO

from pypdf import PdfReader
from pypdf.errors import PdfReadError

from share_errors import InvalidPdfError, AlreadySignedError


MAX_PDF_SIZE = (25 * 1024 * 1024) - (64 * 1024)


def validate_pdf(file_bytes: bytes) -> None:
    """
    Validate PDF before digital signing.

    Raises:
        InvalidPdfError: PDF tidak valid, rusak, terenkripsi,
                         atau ukuran tidak sesuai.
        AlreadySignedError: PDF sudah memiliki tanda tangan.
    """

    if not isinstance(file_bytes, bytes):
        raise InvalidPdfError("File PDF tidak valid.")

    if len(file_bytes) == 0 or len(file_bytes) > MAX_PDF_SIZE:
        raise InvalidPdfError("Ukuran file PDF tidak valid.")

    if b"%PDF-" not in file_bytes[:1024]:
        raise InvalidPdfError("File bukan PDF yang valid.")

    try:
        reader = PdfReader(BytesIO(file_bytes), strict=True)

        if reader.is_encrypted:
            raise InvalidPdfError("PDF terenkripsi tidak diperbolehkan.")

        # Force PDF parsing to detect malformed documents.
        reader.trailer

    except InvalidPdfError:
        raise
    except (PdfReadError, ValueError, TypeError, KeyError, OSError):
        raise InvalidPdfError(
            "PDF rusak atau tidak dapat dibaca."
        ) from None

    try:
        from pdf_verify import extract_signatures

        signatures = extract_signatures(file_bytes)

    except InvalidPdfError:
        raise
    except (PdfReadError, ValueError, TypeError, KeyError, OSError):
        raise InvalidPdfError(
            "Tanda tangan PDF gagal diperiksa."
        ) from None

    if signatures:
        raise AlreadySignedError(
            "PDF sudah memiliki tanda tangan digital."
        )
