import hmac
import io
import re
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from pypdf import PdfReader
from werkzeug.security import generate_password_hash

import db
from certificate import parse_certificate
from cms import parse_cms_signed_data
from pdf_sign import SIGNING_STATEMENT, byte_range_digest, sign_pdf
from share_errors import KeyExpiredError, KeyUnlockError
from signing_keys import (
    find_signer_by_fingerprint,
    generate_signing_keypair,
    get_signing_key,
    rsa_verify,
    signing_public_key_fingerprint,
)

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE_NAMES = ("01_Pemeriksaan_Lab_Word.pdf", "02_Surat_Chrome.pdf")
USERNAME = "dummy_signer"
PASSWORD = "dummy-password-123"
BYTE_RANGE_PATTERN = re.compile(
    rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]"
)


def read_byte_range(signed, original_length):
    match = BYTE_RANGE_PATTERN.search(signed, original_length)
    if match is None:
        raise AssertionError("/ByteRange not found in the update.")
    return [int(number) for number in match.groups()]


class SignPdfIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path_patcher = patch.object(
            db, "DB_PATH", Path(cls.temp_dir.name) / "test.db"
        )
        cls.db_path_patcher.start()
        db.init_db()

        db.create_user(USERNAME, generate_password_hash(PASSWORD))
        cls.user_id = db.get_user_by_username(USERNAME)["id"]

        generate_signing_keypair(cls.user_id, PASSWORD)
        cls.signing_key = get_signing_key(cls.user_id)

        cls.results = {}
        for name in FIXTURE_NAMES:
            original = (FIXTURES / name).read_bytes()
            signed = sign_pdf(original, cls.user_id, PASSWORD)
            cls.results[name] = (original, signed)

    @classmethod
    def tearDownClass(cls):
        cls.db_path_patcher.stop()
        cls.temp_dir.cleanup()

    def signed_parts(self, name):
        original, signed = self.results[name]
        byte_range = read_byte_range(signed, len(original))
        _, a, b, _ = byte_range
        gap = signed[a + 1:b - 1]
        self.assertRegex(gap, rb"\A[0-9A-F]+\Z")
        cms = parse_cms_signed_data(bytes.fromhex(gap.decode("ascii")))
        certificate = parse_certificate(cms["certificate_der"])
        return original, signed, byte_range, cms, certificate

    def test_signed_pdf_keeps_original_and_covers_whole_file(self):
        for name in FIXTURE_NAMES:
            with self.subTest(fixture=name):
                original, signed, byte_range, _, _ = self.signed_parts(name)
                _, a, b, c = byte_range
                self.assertTrue(signed.startswith(original))
                self.assertEqual(signed[a:a + 1], b"<")
                self.assertEqual(signed[b - 1:b], b">")
                self.assertEqual(b + c, len(signed))

    def test_message_digest_matches_byte_range(self):
        for name in FIXTURE_NAMES:
            with self.subTest(fixture=name):
                _, signed, byte_range, cms, _ = self.signed_parts(name)
                self.assertTrue(
                    hmac.compare_digest(
                        cms["message_digest"],
                        byte_range_digest(signed, byte_range),
                    )
                )

    def test_rsa_signature_verifies_with_certificate_key(self):
        for name in FIXTURE_NAMES:
            with self.subTest(fixture=name):
                _, _, _, cms, certificate = self.signed_parts(name)
                self.assertIs(
                    rsa_verify(
                        certificate["public_key_pem"],
                        cms["signed_attrs_der"],
                        cms["signature"],
                    ),
                    True,
                )

    def test_certificate_is_the_stored_one(self):
        for name in FIXTURE_NAMES:
            with self.subTest(fixture=name):
                _, _, _, cms, _ = self.signed_parts(name)
                self.assertEqual(
                    cms["certificate_der"], self.signing_key["certificate_der"]
                )

    def test_fingerprint_finds_the_signer(self):
        for name in FIXTURE_NAMES:
            with self.subTest(fixture=name):
                _, _, _, _, certificate = self.signed_parts(name)
                fingerprint = signing_public_key_fingerprint(
                    certificate["public_key_pem"]
                )
                self.assertEqual(fingerprint, self.signing_key["fingerprint"])
                self.assertEqual(
                    find_signer_by_fingerprint(fingerprint),
                    {"user_id": self.user_id, "username": USERNAME},
                )

    def test_signing_time_matches_pdf_and_certificate(self):
        for name in FIXTURE_NAMES:
            with self.subTest(fixture=name):
                parts = self.signed_parts(name)
                _, signed, byte_range, cms, certificate = parts
                signing_time = cms["signing_time"]
                _, _, b, c = byte_range
                reader = PdfReader(io.BytesIO(signed[:b + c]))
                fields = reader.trailer["/Root"]["/AcroForm"]["/Fields"]
                signature = next(
                    field.get_object()["/V"].get_object()
                    for field in fields
                    if "/V" in field.get_object()
                )

                self.assertEqual(signing_time.microsecond, 0)
                self.assertEqual(
                    signature["/M"],
                    signing_time.strftime("D:%Y%m%d%H%M%S+00'00'"),
                )
                self.assertLessEqual(certificate["not_before"], signing_time)
                self.assertLessEqual(signing_time, certificate["not_after"])
                self.assertEqual(signature["/Name"], USERNAME)
                self.assertEqual(signature["/Reason"], SIGNING_STATEMENT)

    def test_changed_byte_breaks_the_digest(self):
        for name in FIXTURE_NAMES:
            with self.subTest(fixture=name):
                _, signed, byte_range, cms, _ = self.signed_parts(name)
                changed = bytearray(signed)
                changed[10] ^= 0x01
                self.assertNotEqual(
                    byte_range_digest(bytes(changed), byte_range),
                    cms["message_digest"],
                )

    def test_wrong_password(self):
        original, _ = self.results[FIXTURE_NAMES[0]]
        with self.assertRaises(KeyUnlockError):
            sign_pdf(original, self.user_id, "wrong-password")

    def test_expired_key_is_rejected_before_unlock(self):
        original, _ = self.results[FIXTURE_NAMES[0]]
        expires_at = datetime.fromisoformat(self.signing_key["expires_at"])
        before = self.failed_unlock_count()

        one_second_late = expires_at + timedelta(seconds=1)

        with patch("pdf_sign._utc_now", return_value=one_second_late):
            with self.assertRaises(KeyExpiredError):
                sign_pdf(original, self.user_id, "wrong-password")

        self.assertEqual(self.failed_unlock_count(), before)

    def test_key_still_signs_at_the_expiry_second(self):
        original, _ = self.results[FIXTURE_NAMES[0]]
        expires_at = datetime.fromisoformat(self.signing_key["expires_at"])

        with patch("pdf_sign._utc_now", return_value=expires_at):
            signed = sign_pdf(original, self.user_id, PASSWORD)

        byte_range = read_byte_range(signed, len(original))
        _, a, b, _ = byte_range
        gap = signed[a + 1:b - 1].decode("ascii")
        cms = parse_cms_signed_data(bytes.fromhex(gap))

        self.assertEqual(cms["signing_time"], expires_at)
        self.assertEqual(
            cms["message_digest"], byte_range_digest(signed, byte_range)
        )

    def failed_unlock_count(self):
        connection = db.get_connection()
        try:
            return connection.execute(
                "SELECT failed_unlock_count FROM signing_keys "
                "WHERE user_id = ?",
                (self.user_id,),
            ).fetchone()["failed_unlock_count"]
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()