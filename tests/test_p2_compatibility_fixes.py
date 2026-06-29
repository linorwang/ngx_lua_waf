import unittest
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "cache.lua"
CONFIG = ROOT / "config.lua"
WAF = ROOT / "waf.lua"


class P2CompatibilityFixesTest(unittest.TestCase):
    def setUp(self):
        self.cache = CACHE.read_text(encoding="utf-8")
        self.config = CONFIG.read_text(encoding="utf-8")
        self.waf = WAF.read_text(encoding="utf-8")

    def test_config_cache_uses_length_prefixed_format(self):
        self.assertIn('local CONFIG_PREFIX = "waf-config-v1\\n"', self.cache)
        self.assertIn("t[#t+1] = #k..\":\"..k..#v..\":\"..v", self.cache)
        self.assertIn('s:sub(1, #CONFIG_PREFIX) == CONFIG_PREFIX', self.cache)
        self.assertIn('string.gmatch(s, "([^|]+)=([^|]*)|")', self.cache)

    def test_static_request_strips_query_and_fragment(self):
        self.assertIn("ngx.var.uri or ngx.var.request_uri", self.waf)
        self.assertIn('uri = uri:gsub("[?#].*$", "")', self.waf)

    def test_boundary_parser_is_parameter_based(self):
        self.assertIn('headers["content-type"] or headers["Content-Type"]', self.waf)
        self.assertIn('for param in h:gmatch("[^;]+") do', self.waf)
        self.assertIn('name:lower() == "boundary"', self.waf)
        self.assertIn("gsub(\"^'(.*)'$\", \"%1\")", self.waf)

    def test_runtime_config_validation_exists(self):
        self.assertIn("local function validate_runtime_config(c)", self.waf)
        self.assertIn("invalid CCrate config", self.waf)
        self.assertIn("invalid decode_depth config", self.waf)
        self.assertIn("invalid maxRegexLength config", self.waf)
        self.assertIn("runtime_config = validate_runtime_config", self.waf)

    def test_regex_guard_is_configurable(self):
        self.assertIn("maxRegexLength = 512", self.config)
        self.assertIn('rejectUnsafeRegex = "on"', self.config)
        self.assertIn("local function regex_is_too_complex(rule)", self.waf)
        self.assertIn("local function filter_rules(rule_type, rules)", self.waf)
        self.assertIn("skip unsafe regex", self.waf)

    def test_ip_fallback_is_logged(self):
        self.assertIn("not loaded from Redis/cache; falling back to local defaults", self.waf)
        self.assertIn("ip \", list_type", self.waf)

    def test_cc_now_is_not_left_commented_out(self):
        denycc_body = self.waf[self.waf.index("local function denycc()"):self.waf.index("local function get_boundary()")]
        definitions = re.findall(r"(?m)^\s*local now = ngx\.time\(\)", denycc_body)
        self.assertEqual(definitions, ["    local now = ngx.time()"])
        self.assertLess(denycc_body.index("    local now = ngx.time()"),
                        denycc_body.index("cleanup_cc_ban_cache(now, ip)"))


if __name__ == "__main__":
    unittest.main()
