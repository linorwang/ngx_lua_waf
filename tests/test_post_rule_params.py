import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config.lua"
WAF = ROOT / "waf.lua"


def configured_post_rule_types():
    text = CONFIG.read_text(encoding="utf-8")
    rule_params = re.search(r"RuleParams\s*=\s*\{(?P<body>.*?)^\}", text, re.DOTALL | re.MULTILINE)
    if not rule_params:
        return []
    post_rules = re.search(r"post\s*=\s*\{(?P<body>.*?)\}", rule_params.group("body"), re.DOTALL)
    if not post_rules:
        return []
    return re.findall(r'"([^"]+)"|\'([^\']+)\'', post_rules.group("body"))


class PostRuleParamsTest(unittest.TestCase):
    def setUp(self):
        self.waf = WAF.read_text(encoding="utf-8")
        self.post_rule_types = [left or right for left, right in configured_post_rule_types()]

    def test_config_declares_full_post_rule_set(self):
        self.assertEqual(
            self.post_rule_types,
            ["post", "webshell", "pathtraversal", "cmd", "ssrf", "sensitivefile"],
        )

    def test_waf_iterates_configured_post_rule_types(self):
        self.assertIn("config.RuleParams.post", self.waf)
        self.assertIn("for _, rule_type in ipairs(rule_types) do", self.waf)
        self.assertIn("load_rules(rule_type)", self.waf)

    def test_waf_has_post_switches_for_configured_rule_types(self):
        for rule_type in self.post_rule_types:
            with self.subTest(rule_type=rule_type):
                self.assertRegex(self.waf, rf"\b{re.escape(rule_type)}\s*=")


if __name__ == "__main__":
    unittest.main()
