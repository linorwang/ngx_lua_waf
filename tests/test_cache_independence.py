import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "cache.lua"
REDIS = ROOT / "redis.lua"


class CacheIndependenceTest(unittest.TestCase):
    def setUp(self):
        self.cache = CACHE.read_text(encoding="utf-8")
        self.redis = REDIS.read_text(encoding="utf-8")

    def test_cache_does_not_depend_on_global_split(self):
        self.assertNotRegex(self.cache, r"\bsplit\s*\(")
        self.assertNotRegex(self.redis, r"function\s+split\s*\(")
        self.assertIn("local function deserialize_list", self.cache)

    def test_missing_cached_rule_list_is_guarded(self):
        self.assertIn("local function deserialize_list(s)", self.cache)
        self.assertIn("if not s then return nil end", self.cache)

    def test_rule_cache_uses_local_deserializer(self):
        self.assertIn('function _M.get_rules(t) return deserialize_list(_M.get("rules:"..t)) end', self.cache)


if __name__ == "__main__":
    unittest.main()
