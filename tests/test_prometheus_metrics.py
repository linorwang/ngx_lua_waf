import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config.lua"
WAF = ROOT / "waf.lua"
METRICS = ROOT / "metrics.lua"
README = ROOT / "README.md"
INIT_REDIS = ROOT / "admin" / "init_redis.py"


class PrometheusMetricsTest(unittest.TestCase):
    def setUp(self):
        self.config = CONFIG.read_text(encoding="utf-8")
        self.waf = WAF.read_text(encoding="utf-8")
        self.metrics = METRICS.read_text(encoding="utf-8")
        self.readme = README.read_text(encoding="utf-8")
        self.init_redis = INIT_REDIS.read_text(encoding="utf-8")

    def test_metrics_module_defines_low_cardinality_metrics(self):
        self.assertIn('pcall(require, "prometheus")', self.metrics)
        self.assertIn('prometheus_mod.init(dict_name)', self.metrics)
        for metric in [
            "waf_requests_total",
            "waf_blocks_total",
            "waf_rule_matches_total",
            "waf_cc_events_total",
            "waf_body_rejections_total",
            "waf_errors_total",
            "waf_config_reload_total",
            "waf_request_duration_seconds",
        ]:
            with self.subTest(metric=metric):
                self.assertIn(metric, self.metrics)
        self.assertIn('return allowed[kind] and allowed[kind][value] and value or "other"', self.metrics)
        self.assertNotIn('{"ip"', self.metrics)
        self.assertNotIn('{"url"', self.metrics)

    def test_prometheus_config_is_optional_and_initialized(self):
        self.assertIn('prometheus="off"', self.config)
        self.assertIn('prometheusMetricsDict="prometheus_metrics"', self.config)
        self.assertIn("prometheus = prometheus", self.config)
        self.assertIn("prometheusMetricsDict = prometheusMetricsDict", self.config)
        self.assertIn('"prometheus": config.get("prometheus", "off")', self.init_redis)
        self.assertIn('"prometheusMetricsDict": config.get("prometheusMetricsDict", "prometheus_metrics")', self.init_redis)

    def test_waf_records_core_metric_events(self):
        for snippet in [
            "local function ensure_metrics_loaded()",
            'get_config("prometheus", config.prometheus or "off")',
            'call_metrics("request", outcome, waf_request_duration())',
            'record_waf_block(rule_type)',
            'record_rule_match(rule_type)',
            'record_cc_event("limit_exceeded")',
            'record_cc_event("ban_set")',
            'record_cc_event("ban_hit")',
            'record_body_rejection("too_large")',
            'record_waf_block("ip_blocklist")',
            'record_config_reload("success")',
            'record_config_reload("failure")',
        ]:
            with self.subTest(snippet=snippet):
                self.assertIn(snippet, self.waf)

    def test_run_waf_records_request_outcomes(self):
        run_body = self.waf[self.waf.index("local function run_waf()"):]
        self.assertIn("ngx.ctx.waf_start_time", run_body)
        self.assertIn('record_waf_request("skip")', run_body)
        self.assertIn('record_waf_request("allow")', run_body)
        self.assertIn('record_waf_request("error")', run_body)
        self.assertIn('record_waf_error("run")', run_body)

    def test_readme_documents_private_metrics_endpoint(self):
        self.assertIn("Prometheus 指标", self.readme)
        self.assertIn("listen 127.0.0.1:9145;", self.readme)
        self.assertIn('require("metrics").collect()', self.readme)
        self.assertIn("不要把公网业务域名上的 `/metrics` 直接暴露出去", self.readme)


if __name__ == "__main__":
    unittest.main()
