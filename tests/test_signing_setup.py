import importlib
import os
import sqlite3
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch


class _NavLinkParser(HTMLParser):
    """Collect (href, text) of every <a> inside <nav class="nav">.

    Reads the rendered HTML, so whitespace and line breaks in the
    template do not matter.
    """

    def __init__(self):
        super().__init__()
        self.links = []
        self._nav_depth = 0
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "nav" and "nav" in (attrs.get("class") or "").split():
            self._nav_depth += 1
        elif tag == "a" and self._nav_depth:
            self._href = attrs.get("href")
            self._text = []

    def handle_endtag(self, tag):
        if tag == "nav" and self._nav_depth:
            self._nav_depth -= 1
        elif tag == "a" and self._href is not None:
            text = " ".join("".join(self._text).split())
            self.links.append((self._href, text))
            self._href = None

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)


def _nav_links(html):
    parser = _NavLinkParser()
    parser.feed(html)
    return parser.links


class _AppTestCase(unittest.TestCase):
    def setUp(self):
        self.env_patcher = patch.dict(
            os.environ,
            {
                "SECRET_KEY": "dummy-secret-key-for-testing",
                "MASTER_KEY": "11" * 32,
            },
        )
        self.env_patcher.start()
        self.addCleanup(self.env_patcher.stop)

        self.app_module = importlib.import_module("app")
        self.db_module = importlib.import_module("db")
        self.app = self.app_module.app

        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.db_path_patcher = patch.object(
            self.db_module,
            "DB_PATH",
            Path(self.temp_dir.name) / "test.db",
        )
        self.db_path_patcher.start()
        self.addCleanup(self.db_path_patcher.stop)

        self.db_module.init_db()

        self.config_patcher = patch.dict(self.app.config, {"TESTING": True})
        self.config_patcher.start()
        self.addCleanup(self.config_patcher.stop)


class SigningSetupTests(_AppTestCase):
    # --- blueprint ---

    def test_signing_blueprints_are_registered(self):
        for name in ("sign", "verify"):
            with self.subTest(blueprint=name):
                self.assertIn(name, self.app.blueprints)

    def test_signing_blueprints_use_contract_variable_names(self):
        sign_routes = importlib.import_module("sign_routes")
        verify_routes = importlib.import_module("verify_routes")

        self.assertIs(self.app.blueprints["sign"], sign_routes.sign_bp)
        self.assertIs(self.app.blueprints["verify"], verify_routes.verify_bp)

    def test_old_blueprints_still_registered(self):
        for name in ("keys", "requests", "grant", "access"):
            with self.subTest(blueprint=name):
                self.assertIn(name, self.app.blueprints)

    # --- menu ---

    def _dashboard_html(self):
        connection = self.db_module.get_connection()
        try:
            connection.execute(
                "INSERT INTO users (id, username, password_hash) "
                "VALUES (1, 'dummy_user', 'dummy_hash')"
            )
            connection.commit()
        finally:
            connection.close()

        client = self.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = 1

        response = client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def test_menu_has_verify_pdf_link(self):
        links = _nav_links(self._dashboard_html())
        hrefs = [href for href, _ in links]

        self.assertIn("/verify", hrefs)
        verify_text = links[hrefs.index("/verify")][1]
        # The icon is part of the link text, so only check the label.
        self.assertTrue(verify_text.endswith("Verify PDF"), verify_text)

    def test_verify_pdf_link_is_last_in_menu(self):
        hrefs = [href for href, _ in _nav_links(self._dashboard_html())]

        self.assertEqual(hrefs[-1], "/verify")
        self.assertEqual(hrefs[-2], "/shared")

    def test_old_menu_links_still_present(self):
        hrefs = [href for href, _ in _nav_links(self._dashboard_html())]

        for href in ("/keys", "/requests", "/shared"):
            with self.subTest(href=href):
                self.assertIn(href, hrefs)


class ArchivesSignedFieldTests(_AppTestCase):
    def setUp(self):
        super().setUp()
        self._execute(
            "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
            [(1, "dummy_user", "dummy_hash"), (2, "other_user", "dummy_hash")],
        )
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session["user_id"] = 1

    def _execute(self, sql, rows):
        connection = self.db_module.get_connection()
        try:
            with connection:
                connection.executemany(sql, rows)
        finally:
            connection.close()

    def _add_file(self, file_id, owner_id, category="document"):
        self._execute(
            "INSERT INTO medical_files (id, owner_id, category, "
            "aes_storage_name, des_storage_name, rc4_storage_name) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [(file_id, owner_id, category,
              f"{file_id}-aes", f"{file_id}-des", f"{file_id}-rc4")],
        )

    def _add_signature(self, signed_file_id, signer_id, source_file_id=None):
        self._execute(
            "INSERT INTO document_signatures (id, signed_file_id, "
            "source_file_id, signer_id, fingerprint, document_digest, "
            "signed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(f"sig-{signed_file_id}", signed_file_id, source_file_id,
              signer_id, "AAAA BBBB", "00" * 32,
              "2026-11-28T09:30:00+00:00")],
        )

    def _archives(self):
        response = self.client.get("/archives")
        self.assertEqual(response.status_code, 200)
        return {item["id"]: item for item in response.get_json()["archives"]}

    # --- db.get_signed_file_ids_for_owner ---

    def test_db_returns_empty_set_without_signatures(self):
        self._add_file("file-a", 1)
        self.assertEqual(self.db_module.get_signed_file_ids_for_owner(1), set())

    def test_db_returns_only_the_owners_signed_files(self):
        self._add_file("source", 1)
        self._add_file("signed", 1)
        self._add_file("other-source", 2)
        self._add_file("other-signed", 2)
        self._add_signature("signed", 1, "source")
        self._add_signature("other-signed", 2, "other-source")

        self.assertEqual(self.db_module.get_signed_file_ids_for_owner(1), {"signed"})
        self.assertEqual(
            self.db_module.get_signed_file_ids_for_owner(2), {"other-signed"}
        )

    def test_db_uses_one_query(self):
        for number in range(5):
            self._add_file(f"file-{number}", 1)
            self._add_file(f"signed-{number}", 1)
            self._add_signature(f"signed-{number}", 1, f"file-{number}")

        statements = []
        original = self.db_module.get_connection

        def traced_connection():
            connection = original()
            connection.set_trace_callback(statements.append)
            return connection

        with patch.object(self.db_module, "get_connection", traced_connection):
            result = self.db_module.get_signed_file_ids_for_owner(1)

        self.assertEqual(len(result), 5)
        selects = [s for s in statements if s.lstrip().upper().startswith("SELECT")]
        self.assertEqual(len(selects), 1)

    # --- GET /archives ---

    def test_signed_field_is_true_only_for_signed_copies(self):
        self._add_file("source", 1)
        self._add_file("signed", 1)
        self._add_file("video", 1, category="video")
        self._add_signature("signed", 1, "source")

        archives = self._archives()

        self.assertIs(archives["signed"]["signed"], True)
        self.assertIs(archives["source"]["signed"], False)
        self.assertIs(archives["video"]["signed"], False)

    def test_other_users_signatures_do_not_count(self):
        self._add_file("mine", 1)
        self._add_file("theirs", 2)
        self._add_signature("theirs", 2)

        archives = self._archives()

        self.assertEqual(list(archives), ["mine"])
        self.assertIs(archives["mine"]["signed"], False)

    def test_archive_fields_are_unchanged_plus_signed(self):
        self._add_file("file-a", 1)
        item = self._archives()["file-a"]
        self.assertEqual(set(item), {"id", "category", "created_at", "signed"})

    def test_signed_lookup_runs_once_for_all_archives(self):
        for number in range(5):
            self._add_file(f"file-{number}", 1)

        with patch.object(
            self.app_module,
            "get_signed_file_ids_for_owner",
            wraps=self.db_module.get_signed_file_ids_for_owner,
        ) as lookup:
            self._archives()

        lookup.assert_called_once_with(1)

    def test_no_envelope_is_read_or_decrypted(self):
        self._add_file("signed", 1)
        self._add_signature("signed", 1)
        fail = AssertionError("/archives must not read or decrypt files")

        with patch.object(self.app_module, "read_envelope", side_effect=fail), \
                patch.object(self.app_module, "decrypt_blob", side_effect=fail):
            archives = self._archives()

        self.assertIs(archives["signed"]["signed"], True)

    def test_database_error_returns_503(self):
        self._add_file("file-a", 1)
        with patch.object(
            self.app_module,
            "get_signed_file_ids_for_owner",
            side_effect=sqlite3.OperationalError("dummy"),
        ):
            response = self.client.get("/archives")

        self.assertEqual(response.status_code, 503)


if __name__ == "__main__":
    unittest.main()