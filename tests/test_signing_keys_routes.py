import base64
import importlib
import os
import sqlite3
import unittest

from contextlib import closing, ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from werkzeug.http import parse_options_header
from werkzeug.security import generate_password_hash

import db

from certificate import (
    build_self_signed_certificate,
    parse_certificate,
)

from signing_keys import (
    generate_signing_keypair,
    get_signing_key,
    signing_public_key_fingerprint,
    unlock_signing_key,
    rsa_verify,
)

from user_keys import generate_user_keypair


class TestSigningKeysRoutes(unittest.TestCase):

    USER_ID = 1
    OTHER_USER_ID = 2
    EMPTY_USER_ID = 3

    USERNAME = "dummy_signing_user"
    OTHER_USERNAME = "other_signing_user"
    EMPTY_USERNAME = "empty_signing_user"

    PASSWORD = "MedimoSigningTest123!"
    WRONG_PASSWORD = "IncorrectSigningPassword!"

    CSRF_TOKEN = "dummy-signing-csrf-token"

    NOW = datetime(
        2026, 11, 28,
        12, 0, 0,
        tzinfo=timezone.utc,
    )

    GENERATE_URL = "/keys/signing/generate"
    DOWNLOAD_URL = "/keys/signing/certificate"

    @classmethod
    def setUpClass(cls):
        directory = TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)

        cls.seed_path = (
            Path(directory.name)
            / "seed_signing_routes.db"
        )

        cls.password_hash = generate_password_hash(
            cls.PASSWORD,
            method="scrypt:131072:8:1",
        )

        with patch.object(
            db,
            "DB_PATH",
            cls.seed_path,
        ):
            db.init_db()

            with closing(db.get_connection()) as connection:
                with connection:
                    connection.executemany(
                        """
                        INSERT INTO users (
                            id,
                            username,
                            password_hash
                        )
                        VALUES (?, ?, ?)
                        """,
                        (
                            (
                                cls.USER_ID,
                                cls.USERNAME,
                                cls.password_hash,
                            ),
                            (
                                cls.OTHER_USER_ID,
                                cls.OTHER_USERNAME,
                                cls.password_hash,
                            ),
                            (
                                cls.EMPTY_USER_ID,
                                cls.EMPTY_USERNAME,
                                cls.password_hash,
                            ),
                        ),
                    )

            # Genuine, currently valid signing certificate.
            with patch(
                "signing_keys._signing_utc_now",
                return_value=cls.NOW,
            ):
                generate_signing_keypair(
                    cls.USER_ID,
                    cls.PASSWORD,
                )

            # Genuine expired certificate.
            # Do not merely manipulate its expiry metadata.
            with patch(
                "signing_keys._signing_utc_now",
                return_value=datetime(
                    2000, 1, 1,
                    tzinfo=timezone.utc,
                ),
            ):
                generate_signing_keypair(
                    cls.OTHER_USER_ID,
                    cls.PASSWORD,
                )

            # Existing Task 2 encryption keypair.
            generate_user_keypair(
                cls.USER_ID,
                cls.PASSWORD,
            )

            with closing(db.get_connection()) as connection:
                with connection:
                    connection.execute(
                        """
                        UPDATE user_keys
                        SET
                            failed_unlock_count = 5,
                            locked_until = ?
                        WHERE user_id = ?
                        """,
                        (
                            "2099-01-01 00:00:00",
                            cls.USER_ID,
                        ),
                    )

    def setUp(self):
        env_patcher = patch.dict(
            os.environ,
            {
                "SECRET_KEY": "dummy-signing-route-secret",
                "MASTER_KEY": "11" * 32,
            },
        )

        env_patcher.start()
        self.addCleanup(env_patcher.stop)

        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)

        self.db_path = (
            Path(directory.name)
            / "test_signing_routes.db"
        )

        # Every test uses its own isolated database.
        with closing(
            sqlite3.connect(self.seed_path)
        ) as source:
            with closing(
                sqlite3.connect(self.db_path)
            ) as destination:
                source.backup(destination)

        database_patcher = patch.object(
            db,
            "DB_PATH",
            self.db_path,
        )

        database_patcher.start()
        self.addCleanup(database_patcher.stop)

        self.app_module = importlib.import_module(
            "app"
        )

        self.app = self.app_module.app

        config_patcher = patch.dict(
            self.app.config,
            {
                "TESTING": True,
                "SECRET_KEY": "dummy-signing-route-secret",
            },
        )

        config_patcher.start()
        self.addCleanup(config_patcher.stop)

        self.client = self.app.test_client()

        clock_patcher = patch(
            "keys_routes._keys_utc_now",
            return_value=self.NOW,
        )

        self.clock = clock_patcher.start()
        self.addCleanup(clock_patcher.stop)

        generation_clock = patch(
            "signing_keys._signing_utc_now",
            return_value=self.NOW,
        )

        generation_clock.start()
        self.addCleanup(generation_clock.stop)

    # ========================================================
    # Authentication and database fixture helpers
    # ========================================================

    def login(self, user_id=None, *, with_csrf=True):
        if user_id is None:
            user_id = self.USER_ID

        with self.client.session_transaction() as session:
            session.clear()
            session["user_id"] = user_id

            if with_csrf:
                session["csrf_token"] = self.CSRF_TOKEN

    def post_generate(
        self,
        password=None,
        **extra_fields,
    ):
        data = {
            "csrf_token": self.CSRF_TOKEN,
            "password": (
                self.PASSWORD
                if password is None
                else password
            ),
        }

        data.update(extra_fields)

        return self.client.post(
            self.GENERATE_URL,
            data=data,
            follow_redirects=False,
        )

    def execute(self, sql, parameters=()):
        with closing(db.get_connection()) as connection:
            with connection:
                connection.execute(
                    sql,
                    parameters,
                )

    def read_signing_row(self, user_id=None):
        if user_id is None:
            user_id = self.USER_ID

        with closing(db.get_connection()) as connection:
            row = connection.execute(
                """
                SELECT *
                FROM signing_keys
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

        return None if row is None else dict(row)

    def read_encryption_row(self, user_id=None):
        if user_id is None:
            user_id = self.USER_ID

        with closing(db.get_connection()) as connection:
            row = connection.execute(
                """
                SELECT *
                FROM user_keys
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

        return None if row is None else dict(row)

    def signing_count(self):
        with closing(db.get_connection()) as connection:
            return connection.execute(
                "SELECT COUNT(*) FROM signing_keys"
            ).fetchone()[0]

    def audit_rows(self):
        with closing(db.get_connection()) as connection:
            return [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT
                        id,
                        actor_id,
                        file_id,
                        action,
                        created_at
                    FROM signature_audit_log
                    ORDER BY id
                    """
                ).fetchall()
            ]

    def snapshot(self):
        """Capture database contents for read-only assertions."""

        with closing(db.get_connection()) as connection:
            return tuple(connection.iterdump())

    def assert_no_store(self, response):
        self.assertEqual(
            response.headers.get("Cache-Control"),
            "no-store",
        )

    def assert_login_redirect(self, response):
        self.assertIn(
            response.status_code,
            (302, 303),
        )

        self.assertEqual(
            urlsplit(
                response.headers["Location"]
            ).path,
            "/login",
        )

        self.assert_no_store(response)

    def assert_no_audit(self):
        self.assertEqual(
            self.audit_rows(),
            [],
        )

    def assert_safe_password_error(
        self,
        response,
    ):
        self.assertEqual(
            response.status_code,
            400,
        )

        html = response.get_data(
            as_text=True
        )

        self.assertIn(
            "Password tidak dapat diverifikasi.",
            html,
        )

        self.assertNotIn(
            self.WRONG_PASSWORD,
            html,
        )

        self.assertNotIn(
            "Password verification failed.",
            html,
        )

        self.assert_no_store(response)

    # ========================================================
    # Authentication and My Keys page
    # ========================================================

    def test_my_keys_requires_authentication(self):
        response = self.client.get("/keys")

        self.assert_login_redirect(response)

    def test_signing_generation_requires_authentication(self):
        before = self.snapshot()

        with patch(
            "signing_keys.generate_signing_keypair",
            side_effect=AssertionError(
                "Unauthenticated generation reached service"
            ),
        ) as generate:

            response = self.post_generate()

            self.assert_login_redirect(response)
            generate.assert_not_called()

        self.assertEqual(
            self.snapshot(),
            before,
        )

    def test_empty_signing_section_and_csrf_initialization(self):
        self.login(
            self.EMPTY_USER_ID,
            with_csrf=False,
        )

        response = self.client.get("/keys")

        self.assertEqual(
            response.status_code,
            200,
        )

        html = response.get_data(
            as_text=True
        )

        self.assertIn(
            "Encryption key",
            html,
        )

        self.assertIn(
            "No keypair yet",
            html,
        )

        self.assertIn(
            "No signing key yet",
            html,
        )

        self.assertIn(
            'id="generate-keypair-form"',
            html,
        )

        self.assertIn(
            'id="generate-signing-keypair-form"',
            html,
        )

        self.assertIn(
            'action="/keys/signing/generate"',
            html,
        )

        self.assertIn(
            'id="signing-password"',
            html,
        )

        self.assertIn(
            'autocomplete="current-password"',
            html,
        )

        self.assertNotIn(
            'id="download-signing-certificate"',
            html,
        )

        self.assertNotIn(
            'id="copy-signing-fingerprint"',
            html,
        )

        with self.client.session_transaction() as session:
            token = session["csrf_token"]

        self.assertIsInstance(token, str)
        self.assertEqual(len(token), 64)

        self.assertIn(
            f'value="{token}"',
            html,
        )

        self.assert_no_store(response)

    def test_both_key_sections_display_independent_fingerprints(self):
        self.login()

        signing = self.read_signing_row()
        encryption = self.read_encryption_row()
        other = self.read_signing_row(
            self.OTHER_USER_ID
        )

        self.assertNotEqual(
            signing["fingerprint"],
            encryption["fingerprint"],
        )

        response = self.client.get(
            f"/keys?user_id={self.OTHER_USER_ID}"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        html = response.get_data(
            as_text=True
        )

        self.assertIn(
            "Your keypair is ready",
            html,
        )

        self.assertIn(
            "Your signing key is ready",
            html,
        )

        self.assertIn(
            encryption["fingerprint"],
            html,
        )

        self.assertIn(
            signing["fingerprint"],
            html,
        )

        self.assertNotIn(
            other["fingerprint"],
            html,
        )

        self.assertIn(
            'id="copy-fingerprint"',
            html,
        )

        self.assertIn(
            'id="copy-signing-fingerprint"',
            html,
        )

        self.assertIn(
            'id="download-signing-certificate"',
            html,
        )

        self.assertNotIn(
            'id="generate-keypair-form"',
            html,
        )

        self.assertNotIn(
            'id="generate-signing-keypair-form"',
            html,
        )

        self.assert_no_store(response)

    def test_certificate_information_and_wib_expiration(self):
        self.login()

        row = self.read_signing_row()

        certificate = parse_certificate(
            row["certificate_der"]
        )

        expires_wib = (
            certificate["not_after"]
            .astimezone(
                ZoneInfo("Asia/Jakarta")
            )
            .strftime(
                "%d %b %Y, %H:%M:%S WIB"
            )
        )

        valid_from_wib = (
            certificate["not_before"]
            .astimezone(
                ZoneInfo("Asia/Jakarta")
            )
            .strftime(
                "%d %b %Y, %H:%M:%S WIB"
            )
        )

        response = self.client.get("/keys")

        self.assertEqual(
            response.status_code,
            200,
        )

        html = response.get_data(
            as_text=True
        )

        self.assertIn(
            certificate["subject_cn"],
            html,
        )

        self.assertIn(
            "Self-signed X.509",
            html,
        )

        self.assertIn(
            expires_wib,
            html,
        )

        self.assertIn(
            valid_from_wib,
            html,
        )

        self.assertIn(
            "Within validity period",
            html,
        )

        self.assertIn(
            "does not establish external certificate trust",
            html,
        )

        self.assertEqual(
            certificate["not_after"]
            - certificate["not_before"],
            timedelta(days=730),
        )

        self.assert_no_store(response)

    def test_expired_and_not_yet_valid_certificate_status(self):
        self.login(
            self.OTHER_USER_ID
        )

        expired_page = self.client.get("/keys")

        self.assertEqual(
            expired_page.status_code,
            200,
        )

        html = expired_page.get_data(
            as_text=True
        )

        self.assertIn(
            "Expired",
            html,
        )

        self.assertIn(
            "Kunci tanda tangan Anda sudah kedaluwarsa.",
            html,
        )

        self.assertIn(
            'id="download-signing-certificate"',
            html,
        )

        self.assertNotIn(
            'id="generate-signing-keypair-form"',
            html,
        )

        self.login(self.USER_ID)

        self.clock.return_value = (
            self.NOW - timedelta(seconds=1)
        )

        future_page = self.client.get("/keys")

        self.assertEqual(
            future_page.status_code,
            200,
        )

        self.assertIn(
            "Not yet valid",
            future_page.get_data(
                as_text=True
            ),
        )

        self.assert_no_store(expired_page)
        self.assert_no_store(future_page)

    def test_certificate_subject_is_html_escaped(self):
        hostile_username = (
            "<script>alert(1)</script>"
        )

        original = parse_certificate(
            self.read_signing_row()[
                "certificate_der"
            ]
        )

        # Use real cryptography to create a certificate
        # with intentionally hostile display data.
        private_key = unlock_signing_key(
            self.USER_ID,
            self.PASSWORD,
        )

        certificate = build_self_signed_certificate(
            private_key,
            hostile_username,
            original["not_before"],
            original["not_after"],
        )

        self.execute(
            """
            UPDATE users
            SET username = ?
            WHERE id = ?
            """,
            (
                hostile_username,
                self.USER_ID,
            ),
        )

        self.execute(
            """
            UPDATE signing_keys
            SET certificate_der = ?
            WHERE user_id = ?
            """,
            (
                certificate,
                self.USER_ID,
            ),
        )

        self.login()

        response = self.client.get("/keys")

        self.assertEqual(
            response.status_code,
            200,
        )

        html = response.get_data(
            as_text=True
        )

        self.assertNotIn(
            hostile_username,
            html,
        )

        self.assertIn(
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            html,
        )

    def test_my_keys_does_not_expose_private_material(self):
        self.login()

        signing = self.read_signing_row()
        encryption = self.read_encryption_row()

        response = self.client.get("/keys")

        self.assertEqual(
            response.status_code,
            200,
        )

        html = response.get_data(
            as_text=True
        )

        forbidden_strings = (
            self.PASSWORD,
            self.password_hash,
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN PUBLIC KEY-----",
            "encrypted_private_key",
            "private_key_salt",
            "failed_unlock_count",
            "locked_until",
            signing["certificate_der"].hex(),
            base64.b64encode(
                signing["certificate_der"]
            ).decode("ascii"),
        )

        for value in forbidden_strings:
            with self.subTest(
                value_type=type(value).__name__
            ):
                self.assertNotIn(
                    value,
                    html,
                )

        for row in (signing, encryption):
            for name in (
                "private_key_salt",
                "encrypted_private_key",
            ):
                secret = row[name]

                self.assertNotIn(
                    secret.hex(),
                    html,
                )

                self.assertNotIn(
                    base64.b64encode(secret).decode("ascii"),
                    html,
                )

        with self.client.session_transaction() as session:
            session_text = repr(dict(session))

        self.assertNotIn(
            self.PASSWORD,
            session_text,
        )

        self.assertNotIn(
            self.password_hash,
            session_text,
        )

        self.assert_no_store(response)

    # ========================================================
    # Signing key generation routes
    # ========================================================

    def test_successful_generation_uses_session_and_audits_once(self):
        # Simulate an account with an existing Task 2 keypair
        # but without a signing keypair.
        self.execute(
            """
            DELETE FROM signing_keys
            WHERE user_id = ?
            """,
            (self.USER_ID,),
        )

        encryption_before = self.read_encryption_row()

        other_before = self.read_signing_row(
            self.OTHER_USER_ID
        )

        count_before = self.signing_count()

        self.login(self.USER_ID)

        # Attempt to override the authenticated target.
        response = self.post_generate(
            user_id=str(self.OTHER_USER_ID),
            owner_id=str(self.EMPTY_USER_ID),
        )

        self.assertEqual(
            response.status_code,
            303,
        )

        self.assertEqual(
            urlsplit(
                response.headers["Location"]
            ).path,
            "/keys",
        )

        self.assert_no_store(response)

        row = self.read_signing_row(
            self.USER_ID
        )

        self.assertIsNotNone(row)

        self.assertEqual(
            self.signing_count(),
            count_before + 1,
        )

        self.assertEqual(
            self.read_signing_row(
                self.OTHER_USER_ID
            ),
            other_before,
        )

        self.assertIsNone(
            self.read_signing_row(
                self.EMPTY_USER_ID
            )
        )

        self.assertEqual(
            self.read_encryption_row(),
            encryption_before,
        )

        self.assertNotEqual(
            row["fingerprint"],
            encryption_before["fingerprint"],
        )

        certificate = parse_certificate(
            row["certificate_der"]
        )

        self.assertEqual(
            certificate["subject_cn"],
            self.USERNAME,
        )

        self.assertEqual(
            signing_public_key_fingerprint(
                certificate["public_key_pem"]
            ),
            row["fingerprint"],
        )

        self.assertTrue(
            rsa_verify(
                certificate["public_key_pem"],
                certificate["tbs_der"],
                certificate["signature"],
            )
        )

        self.assertEqual(
            certificate["not_after"],
            datetime.fromisoformat(
                row["expires_at"]
            ),
        )

        self.assertEqual(
            row["failed_unlock_count"],
            0,
        )

        self.assertIsNone(
            row["locked_until"]
        )

        audits = self.audit_rows()

        self.assertEqual(
            len(audits),
            1,
        )

        event = audits[0]

        self.assertEqual(
            event["actor_id"],
            self.USER_ID,
        )

        self.assertIsNone(
            event["file_id"]
        )

        self.assertEqual(
            event["action"],
            "key_generated",
        )

        self.assertEqual(
            datetime.fromisoformat(
                event["created_at"]
            ).utcoffset(),
            timedelta(0),
        )

        page = self.client.get(
            response.headers["Location"]
        )

        html = page.get_data(
            as_text=True
        )

        self.assertIn(
            "Your signing keypair has been generated successfully.",
            html,
        )

        self.assertIn(
            row["fingerprint"],
            html,
        )

        self.assertIn(
            encryption_before["fingerprint"],
            html,
        )

        self.assertNotIn(
            self.PASSWORD,
            html,
        )

        self.assertNotIn(
            'id="generate-signing-keypair-form"',
            html,
        )

        # Refreshing and submitting again must not produce
        # another signing key or successful audit event.
        self.client.get("/keys")

        duplicate = self.post_generate()

        self.assertEqual(
            duplicate.status_code,
            409,
        )

        self.assertEqual(
            self.read_signing_row(),
            row,
        )

        self.assertEqual(
            self.audit_rows(),
            audits,
        )

        self.assertEqual(
            self.read_encryption_row(),
            encryption_before,
        )

    def test_missing_and_empty_password_are_rejected(self):
        self.login(self.EMPTY_USER_ID)

        before = self.snapshot()

        with patch(
            "signing_keys.generate_signing_keypair",
            side_effect=AssertionError(
                "Empty password reached generation"
            ),
        ) as generate:

            cases = (
                {
                    "csrf_token": self.CSRF_TOKEN,
                },
                {
                    "csrf_token": self.CSRF_TOKEN,
                    "password": "",
                },
            )

            for data in cases:
                with self.subTest(data=data):
                    response = self.client.post(
                        self.GENERATE_URL,
                        data=data,
                    )

                    self.assert_safe_password_error(
                        response
                    )

            generate.assert_not_called()

        self.assertEqual(
            self.snapshot(),
            before,
        )

        self.assert_no_audit()

    def test_wrong_password_is_rejected_without_audit(self):
        self.login(self.EMPTY_USER_ID)

        before = self.snapshot()

        response = self.post_generate(
            password=self.WRONG_PASSWORD
        )

        self.assert_safe_password_error(
            response
        )

        self.assertIsNone(
            self.read_signing_row(
                self.EMPTY_USER_ID
            )
        )

        self.assertEqual(
            self.snapshot(),
            before,
        )

        self.assert_no_audit()

    def test_missing_or_invalid_csrf_rejects_generation(self):
        before = self.snapshot()

        with patch(
            "signing_keys.generate_signing_keypair",
            side_effect=AssertionError(
                "Invalid CSRF reached generation"
            ),
        ) as generate:

            cases = (
                (True, None),
                (True, ""),
                (True, "incorrect-token"),
                (False, self.CSRF_TOKEN),
            )

            for session_token, submitted in cases:
                with self.subTest(
                    session_token=session_token,
                    submitted=submitted,
                ):
                    self.login(
                        self.EMPTY_USER_ID,
                        with_csrf=session_token,
                    )

                    data = {
                        "password": self.PASSWORD
                    }

                    if submitted is not None:
                        data["csrf_token"] = submitted

                    response = self.client.post(
                        self.GENERATE_URL,
                        data=data,
                    )

                    self.assertEqual(
                        response.status_code,
                        400,
                    )

                    self.assert_no_store(response)

            generate.assert_not_called()

        self.assertEqual(
            self.snapshot(),
            before,
        )

        self.assert_no_audit()

    def test_duplicate_generation_does_not_replace_key(self):
        self.login()

        before = self.snapshot()

        with patch(
            "signing_keys.generate_signing_keypair",
            side_effect=AssertionError(
                "Duplicate generation reached service"
            ),
        ) as generate:

            response = self.post_generate()

            generate.assert_not_called()

        self.assertEqual(
            response.status_code,
            409,
        )

        self.assertIn(
            "You already have a signing keypair.",
            response.get_data(
                as_text=True
            ),
        )

        self.assertEqual(
            self.snapshot(),
            before,
        )

        self.assert_no_audit()
        self.assert_no_store(response)

    def test_concurrent_duplicate_does_not_create_second_audit(self):
        self.login(self.EMPTY_USER_ID)

        original_generate = (
            generate_signing_keypair
        )

        def competing_generation(
            user_id,
            password,
        ):
            # Simulate the other request winning the race.
            # The competing key is generated using real crypto.
            original_generate(
                user_id,
                password,
            )

            db.record_signature_event(
                user_id,
                None,
                "key_generated",
            )

            raise ValueError(
                "User already has a signing keypair."
            )

        before = self.signing_count()

        with patch(
            "signing_keys.generate_signing_keypair",
            side_effect=competing_generation,
        ):
            response = self.post_generate()

        self.assertEqual(
            response.status_code,
            409,
        )

        self.assertEqual(
            self.signing_count(),
            before + 1,
        )

        self.assertIsNotNone(
            self.read_signing_row(
                self.EMPTY_USER_ID
            )
        )

        audits = self.audit_rows()

        self.assertEqual(len(audits), 1)

        self.assertEqual(
            audits[0]["actor_id"],
            self.EMPTY_USER_ID,
        )

        self.assertEqual(
            audits[0]["action"],
            "key_generated",
        )

        self.assert_no_store(response)

    def test_generation_internal_errors_are_safe(self):
        self.login(self.EMPTY_USER_ID)

        before = self.snapshot()

        failures = (
            sqlite3.OperationalError(
                "Sensitive internal database details"
            ),
            RuntimeError(
                "Sensitive internal crypto details"
            ),
            ValueError(
                "Unexpected key validation details"
            ),
        )

        for failure in failures:
            with self.subTest(
                error=type(failure).__name__
            ):
                with patch(
                    "signing_keys.generate_signing_keypair",
                    side_effect=failure,
                ):
                    response = self.post_generate()

                self.assertEqual(
                    response.status_code,
                    503,
                )

                self.assertNotIn(
                    str(failure),
                    response.get_data(
                        as_text=True
                    ),
                )

                self.assert_no_store(response)

        self.assertEqual(
            self.snapshot(),
            before,
        )

        self.assert_no_audit()

    def test_audit_failure_does_not_regenerate_or_delete_key(self):
        self.login(self.EMPTY_USER_ID)

        before = self.signing_count()

        # A real SQLite audit insertion failure.
        self.execute(
            """
            CREATE TRIGGER test_fail_key_generated_audit
            BEFORE INSERT ON signature_audit_log
            WHEN NEW.action = 'key_generated'
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'Internal audit insertion failure'
                );
            END
            """
        )

        response = self.post_generate()

        self.assertEqual(
            response.status_code,
            503,
        )

        html = response.get_data(
            as_text=True
        )

        self.assertIn(
            "Your signing key was created",
            html,
        )

        self.assertNotIn(
            "Internal audit insertion failure",
            html,
        )

        row = self.read_signing_row(
            self.EMPTY_USER_ID
        )

        self.assertIsNotNone(row)

        self.assertEqual(
            self.signing_count(),
            before + 1,
        )

        self.assert_no_audit()

        self.execute(
            """
            DROP TRIGGER test_fail_key_generated_audit
            """
        )

        duplicate = self.post_generate()

        self.assertEqual(
            duplicate.status_code,
            409,
        )

        self.assertEqual(
            self.read_signing_row(
                self.EMPTY_USER_ID
            ),
            row,
        )

        self.assert_no_audit()
        self.assert_no_store(response)

    # ========================================================
    # Certificate download routes
    # ========================================================

    def test_certificate_download_exact_bytes_and_headers(self):
        self.login()

        row = self.read_signing_row()
        before = self.snapshot()

        response = self.client.get(
            self.DOWNLOAD_URL
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            response.data,
            row["certificate_der"],
        )

        self.assertEqual(
            response.mimetype,
            "application/pkix-cert",
        )

        disposition, parameters = (
            parse_options_header(
                response.headers[
                    "Content-Disposition"
                ]
            )
        )

        self.assertEqual(
            disposition,
            "attachment",
        )

        self.assertEqual(
            parameters["filename"],
            f"medimo-{self.USERNAME}.cer",
        )

        self.assertEqual(
            response.headers.get(
                "X-Content-Type-Options"
            ),
            "nosniff",
        )

        self.assertNotIn(
            row["encrypted_private_key"],
            response.data,
        )

        self.assertEqual(
            parse_certificate(response.data)[
                "subject_cn"
            ],
            self.USERNAME,
        )

        self.assertEqual(
            self.snapshot(),
            before,
        )

        self.assert_no_store(response)

    def test_certificate_download_missing_and_unauthenticated(self):
        response = self.client.get(
            self.DOWNLOAD_URL
        )

        self.assert_login_redirect(response)

        self.login(self.EMPTY_USER_ID)

        missing = self.client.get(
            self.DOWNLOAD_URL
        )

        self.assertEqual(
            missing.status_code,
            404,
        )

        self.assertNotIn(
            "Content-Disposition",
            missing.headers,
        )

        self.assert_no_store(missing)

    def test_certificate_download_enforces_session_user(self):
        before = self.snapshot()

        own = self.read_signing_row(
            self.USER_ID
        )

        other = self.read_signing_row(
            self.OTHER_USER_ID
        )

        self.assertNotEqual(
            own["certificate_der"],
            other["certificate_der"],
        )

        self.login(self.USER_ID)

        forged_url = (
            f"{self.DOWNLOAD_URL}"
            f"?user_id={self.OTHER_USER_ID}"
        )

        response = self.client.get(
            forged_url
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            response.data,
            own["certificate_der"],
        )

        self.assertNotEqual(
            response.data,
            other["certificate_der"],
        )

        self.login(self.OTHER_USER_ID)

        other_response = self.client.get(
            f"{self.DOWNLOAD_URL}"
            f"?user_id={self.USER_ID}"
        )

        self.assertEqual(
            other_response.data,
            other["certificate_der"],
        )

        # An account without a key cannot fetch somebody
        # else's certificate through this endpoint.
        self.login(self.EMPTY_USER_ID)

        denied = self.client.get(
            forged_url
        )

        self.assertEqual(
            denied.status_code,
            404,
        )

        self.assertEqual(
            self.snapshot(),
            before,
        )

    def test_expired_certificate_remains_downloadable(self):
        self.login(self.OTHER_USER_ID)

        row = self.read_signing_row(
            self.OTHER_USER_ID
        )

        self.assertLess(
            datetime.fromisoformat(
                row["expires_at"]
            ),
            self.NOW,
        )

        response = self.client.get(
            self.DOWNLOAD_URL
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            response.data,
            row["certificate_der"],
        )

        self.assert_no_store(response)
        self.assert_no_audit()

    def test_public_reads_do_not_unlock_or_modify_keys(self):
        self.login()

        self.execute(
            """
            UPDATE signing_keys
            SET
                failed_unlock_count = 5,
                locked_until = ?
            WHERE user_id = ?
            """,
            (
                (
                    self.NOW
                    + timedelta(minutes=15)
                ).isoformat(),
                self.USER_ID,
            ),
        )

        before = self.snapshot()

        forbidden_operations = (
            "signing_keys._derive_signing_kek",
            "signing_keys.scrypt",
            "signing_keys.decrypt_blob",
            "signing_keys.unlock_signing_key",
            "crypto_core.decrypt_blob",
            "user_keys._derive_kek",
            "user_keys.unlock_private_key",
        )

        with ExitStack() as stack:
            mocks = [
                stack.enter_context(
                    patch(
                        name,
                        side_effect=AssertionError(
                            f"Unexpected private-key operation: {name}"
                        ),
                    )
                )
                for name in forbidden_operations
            ]

            page = self.client.get("/keys")

            download = self.client.get(
                self.DOWNLOAD_URL
            )

            self.assertEqual(
                page.status_code,
                200,
            )

            self.assertEqual(
                download.status_code,
                200,
            )

            self.assertEqual(
                download.data,
                self.read_signing_row()[
                    "certificate_der"
                ],
            )

            for mocked in mocks:
                mocked.assert_not_called()

        self.assertEqual(
            self.snapshot(),
            before,
        )

        self.assert_no_audit()
        self.assert_no_store(page)
        self.assert_no_store(download)

    def test_certificate_download_filename_is_safe(self):
        self.login()

        self.execute(
            """
            UPDATE users
            SET username = ?
            WHERE id = ?
            """,
            (
                "../../evil\r\nX-Injected: yes",
                self.USER_ID,
            ),
        )

        response = self.client.get(
            self.DOWNLOAD_URL
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        _, parameters = parse_options_header(
            response.headers[
                "Content-Disposition"
            ]
        )

        filename = parameters["filename"]

        self.assertTrue(
            filename.endswith(".cer")
        )

        for unsafe in (
            "/",
            "\\",
            "\r",
            "\n",
        ):
            self.assertNotIn(
                unsafe,
                filename,
            )

        self.assertNotIn(
            "X-Injected",
            response.headers,
        )

        self.assertEqual(
            response.data,
            self.read_signing_row()[
                "certificate_der"
            ],
        )

        self.assert_no_store(response)

    # ========================================================
    # Defensive route boundaries
    # ========================================================

    def test_database_failures_are_not_exposed(self):
        self.login(self.EMPTY_USER_ID)

        before = self.snapshot()

        with patch(
            "signing_keys.get_signing_key",
            side_effect=sqlite3.OperationalError(
                "Sensitive database lookup details"
            ),
        ):
            responses = (
                self.client.get("/keys"),
                self.post_generate(),
                self.client.get(self.DOWNLOAD_URL),
            )

        for response in responses:
            with self.subTest(
                status=response.status_code
            ):
                self.assertEqual(
                    response.status_code,
                    503,
                )

                self.assertNotIn(
                    "Sensitive database lookup details",
                    response.get_data(
                        as_text=True
                    ),
                )

                self.assert_no_store(response)

        self.assertEqual(
            self.snapshot(),
            before,
        )

    def test_corrupted_certificate_is_not_rendered_or_downloaded(self):
        self.login()

        self.execute(
            """
            UPDATE signing_keys
            SET certificate_der = ?
            WHERE user_id = ?
            """,
            (
                b"\x30\x00",
                self.USER_ID,
            ),
        )

        before = self.snapshot()

        page = self.client.get("/keys")
        download = self.client.get(
            self.DOWNLOAD_URL
        )

        for response in (page, download):
            self.assertEqual(
                response.status_code,
                503,
            )

            self.assertNotIn(
                "Content-Disposition",
                response.headers,
            )

            self.assert_no_store(response)

        self.assertEqual(
            self.snapshot(),
            before,
        )

    def test_deleted_session_account_is_rejected(self):
        before = self.snapshot()

        for operation in (
            lambda: self.client.get("/keys"),
            lambda: self.post_generate(),
            lambda: self.client.get(
                self.DOWNLOAD_URL
            ),
        ):
            self.login(999999)

            response = operation()

            self.assert_login_redirect(
                response
            )

            with self.client.session_transaction() as session:
                self.assertNotIn(
                    "user_id",
                    session,
                )

        self.assertEqual(
            self.snapshot(),
            before,
        )

        self.assert_no_audit()

    def test_generation_route_requires_post(self):
        self.login(self.EMPTY_USER_ID)

        before = self.snapshot()

        response = self.client.get(
            self.GENERATE_URL
        )

        self.assertEqual(
            response.status_code,
            405,
        )

        self.assert_no_store(response)

        self.assertEqual(
            self.snapshot(),
            before,
        )

        self.assert_no_audit()


if __name__ == "__main__":
    unittest.main()