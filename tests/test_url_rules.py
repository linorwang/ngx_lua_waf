import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
URL_RULES = ROOT / "wafconf" / "url"


def load_url_rules():
    return [
        line.strip()
        for line in URL_RULES.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def matches_any_rule(url, rules):
    return any(re.search(rule, url, re.IGNORECASE) for rule in rules)


class DefaultUrlRulesTest(unittest.TestCase):
    def setUp(self):
        self.rules = load_url_rules()

    def test_default_url_rules_do_not_match_everyday_urls(self):
        safe_urls = [
            "/",
            "/index.html",
            "/api/users?id=1",
            "/static/app.js",
            "/assets/style.css",
        ]

        for url in safe_urls:
            with self.subTest(url=url):
                self.assertFalse(matches_any_rule(url, self.rules))

    def test_default_url_rules_still_match_sensitive_extensions(self):
        blocked_urls = [
            "/backup.sql",
            "/backup.zip",
            "/db.bak",
            "/old.inc",
            "/WEB-INF/classes/App.class",
        ]

        for url in blocked_urls:
            with self.subTest(url=url):
                self.assertTrue(matches_any_rule(url, self.rules))

    def test_default_url_rules_do_not_match_empty_url(self):
        self.assertFalse(matches_any_rule("", self.rules))


if __name__ == "__main__":
    unittest.main()
