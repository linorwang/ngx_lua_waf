import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config.lua"
README = ROOT / "README.md"
WAF = ROOT / "waf.lua"
INIT_REDIS = ROOT / "admin" / "init_redis.py"


class SecurityEnhancementsTest(unittest.TestCase):
    def setUp(self):
        self.config = CONFIG.read_text(encoding="utf-8")
        self.readme = README.read_text(encoding="utf-8")
        self.waf = WAF.read_text(encoding="utf-8")
        self.init_redis = INIT_REDIS.read_text(encoding="utf-8")

    def test_redis_credentials_remain_static_config_values(self):
        self.assertIn('redis_username = "yanfa"', self.config)
        self.assertIn('redis_password = "BTh44gxWmp6FjhR6"', self.config)
        self.assertNotIn("os.getenv", self.config)
        self.assertNotIn("os.getenv", self.waf)

    def test_request_body_size_limit_is_enforced(self):
        self.assertIn("maxRequestBodySize=10485760", self.config)
        self.assertIn("local function request_body_too_large()", self.waf)
        self.assertIn("local function body_data_too_large(body_data)", self.waf)
        self.assertIn("local function reject_large_body(size)", self.waf)
        self.assertIn("HTTP_REQUEST_ENTITY_TOO_LARGE or 413", self.waf)

    def test_alerting_uses_shared_counter(self):
        self.assertIn('alertEnabled="on"', self.config)
        self.assertIn("alertThreshold=100", self.config)
        self.assertIn("local function alert_event(tag)", self.waf)
        self.assertIn("alert threshold reached", self.waf)
        self.assertIn("alert_event(tag)", self.waf)

    def test_reload_api_is_exported_and_token_guarded(self):
        self.assertIn("reloadToken=nil", self.config)
        self.assertIn("local function reload_waf(token)", self.waf)
        self.assertIn("reload rejected: invalid token", self.waf)
        self.assertIn("_M.reload = reload_waf", self.waf)
        self.assertIn("waf.reload(ngx.var.arg_token)", self.readme)

    def test_redis_initialization_includes_security_config(self):
        for key in [
            "realIpHeaders",
            "trustedProxyIps",
            "bodyInspectMethods",
            "maxRequestBodySize",
            "alertEnabled",
            "alertThreshold",
            "alertWindow",
            "reloadToken",
        ]:
            with self.subTest(key=key):
                self.assertRegex(self.init_redis, rf'"{re.escape(key)}"\s*:')
        self.assertIn("def redis_config_value(value):", self.init_redis)
        self.assertIn('return ",".join(str(item) for item in value)', self.init_redis)

    def test_denycc_now_is_real_code_once(self):
        denycc_body = self.waf[self.waf.index("local function denycc()"):self.waf.index("local function get_boundary()")]
        definitions = re.findall(r"(?m)^\s*local now = ngx\.time\(\)", denycc_body)
        self.assertEqual(definitions, ["    local now = ngx.time()"])


if __name__ == "__main__":
    unittest.main()
