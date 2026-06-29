import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config.lua"
README = ROOT / "README.md"
WAF = ROOT / "waf.lua"


class P1StabilityFixesTest(unittest.TestCase):
    def setUp(self):
        self.config = CONFIG.read_text(encoding="utf-8")
        self.readme = README.read_text(encoding="utf-8")
        self.waf = WAF.read_text(encoding="utf-8")

    def test_enable_cache_is_defined_once(self):
        definitions = re.findall(r"(?m)^enable_cache\s*=", self.config)
        self.assertEqual(definitions, ["enable_cache ="])

    def test_body_inspection_covers_write_methods(self):
        self.assertIn('bodyInspectMethods={"POST","PUT","PATCH","DELETE"}', self.config)
        self.assertIn("local function should_inspect_body(method)", self.waf)
        self.assertIn("if should_inspect_body(method) then", self.waf)
        self.assertNotIn('if method == "POST" then', self.waf)

    def test_log_directory_failures_are_not_silent(self):
        self.assertIn("local function ensure_log_dir(dir)", self.waf)
        self.assertIn('"mkdir -p "', self.waf)
        self.assertIn("pcall(os.execute", self.waf)
        self.assertIn("[WAF] failed to write attack log", self.waf)

    def test_shared_dicts_are_validated_and_documented(self):
        self.assertIn("local function validate_shared_dicts()", self.waf)
        self.assertIn("missing lua_shared_dict limit", self.waf)
        self.assertIn("missing lua_shared_dict waf_cache", self.waf)
        self.assertIn("lua_shared_dict limit 100m;", self.readme)
        self.assertIn("lua_shared_dict waf_cache 50m;", self.readme)

    def test_cc_cache_has_frequent_expiry_cleanup(self):
        self.assertIn("CCCleanupInterval=1", self.config)
        self.assertIn("local function cleanup_cc_ban_cache(now, current_ip)", self.waf)
        self.assertIn("cleanup_cc_ban_cache(now, ip)", self.waf)


if __name__ == "__main__":
    unittest.main()
