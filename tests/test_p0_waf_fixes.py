import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config.lua"
WAF = ROOT / "waf.lua"


class P0WafFixesTest(unittest.TestCase):
    def setUp(self):
        self.config = CONFIG.read_text(encoding="utf-8")
        self.waf = WAF.read_text(encoding="utf-8")

    def test_real_ip_uses_trusted_proxy_configuration(self):
        self.assertIn("realIpHeaders", self.config)
        self.assertIn("trustedProxyIps", self.config)
        self.assertIn("local function getClientIp()", self.waf)
        self.assertIn("is_trusted_proxy(remote_ip)", self.waf)
        self.assertIn('"x-forwarded-for"', self.waf.lower())
        self.assertIn("for i = #ips, 1, -1 do", self.waf)
        self.assertIn("if not is_trusted_proxy(ips[i]) then return ips[i] end", self.waf)

    def test_real_ip_validation_is_strict(self):
        ip_body = self.waf[self.waf.index("local function is_ip_token(ip)"):self.waf.index("local function is_trusted_proxy(remote_ip)")]
        self.assertIn('ip:match("^%d+%.%d+%.%d+%.%d+$")', ip_body)
        self.assertIn("n < 0 or n > 255", ip_body)
        self.assertIn("groups == 8", ip_body)

    def test_cc_limit_defaults_to_ip_scope(self):
        self.assertRegex(self.config, r'CCScope\s*=\s*"ip"')
        self.assertIn('return "cc:"..ip', self.waf)
        self.assertNotIn("ip..uri", self.waf)

    def test_cc_limit_uses_atomic_shared_counter(self):
        denycc_body = self.waf[self.waf.index("local function denycc()"):self.waf.index("local function get_boundary()")]
        self.assertIn("shared_incr_with_ttl(limit, token, sec)", denycc_body)
        self.assertIn("if req > cnt then", denycc_body)
        self.assertNotIn("local req = limit:get(token)", denycc_body)

    def test_white_url_runs_before_cc_check(self):
        run_body = self.waf[self.waf.index("local function run_waf()") :]
        self.assertLess(run_body.index("if whiteurl() then return end"), run_body.index("if denycc() then return end"))

    def test_cc_block_status_matches_forbidden_page(self):
        self.assertNotIn("HTTP_SERVICE_UNAVAILABLE", self.waf)
        self.assertIn("HTTP_FORBIDDEN", self.waf)

    def test_file_extension_check_is_exact_match(self):
        self.assertIn("if ext == tostring(v):lower() then", self.waf)
        file_ext_body = re.search(r"local function fileExtCheck\(ext\)(.*?)\nend", self.waf, re.DOTALL)
        self.assertIsNotNone(file_ext_body)
        self.assertNotIn("safe_match(ext, v", file_ext_body.group(1))


if __name__ == "__main__":
    unittest.main()
