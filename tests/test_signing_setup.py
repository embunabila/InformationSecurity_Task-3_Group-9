import importlib
import os
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


class SigningSetupTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()