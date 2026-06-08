#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import re
import sys

script_dir = os.path.dirname(os.path.abspath(__file__))
repo_dir = os.path.abspath(os.path.join(script_dir, ".."))
sys.path.insert(0, repo_dir)


def read_config():
    config = {}
    config_path = os.path.join(repo_dir, "config.lua")

    with open(config_path, "r", encoding="utf-8") as f:
        content = f.read()

    content = re.sub(r"--\[\[.*?\]\]", "", content, flags=re.DOTALL)
    content = re.sub(r"--.*$", "", content, flags=re.MULTILINE)
    content = content.split("local _M =")[0]

    def parse_simple_value(value_str):
        value_str = value_str.strip()
        if value_str == "true":
            return True
        if value_str == "false":
            return False
        if value_str == "nil":
            return None
        if value_str.startswith('"') or value_str.startswith("'"):
            return value_str[1:-1]
        return value_str

    def parse_array(value_str):
        items = []
        for item in re.findall(r'"([^"]+)"|\'([^\']+)\'', value_str):
            items.append(item[0] or item[1])
        return items

    html_match = re.search(r"html\s*=\s*\[\[(.*?)\]\]", content, re.DOTALL)
    if html_match:
        config["html"] = html_match.group(1)
        content = re.sub(r"html\s*=\s*\[\[.*?\]\]", "", content, flags=re.DOTALL)

    array_pattern = r"^(\w+)\s*=\s*(\{.*?\})$"
    for match in re.finditer(array_pattern, content, re.DOTALL | re.MULTILINE):
        config[match.group(1)] = parse_array(match.group(2))

    simple_pattern = r"^(\w+)\s*=\s*([^={\n]+)$"
    for match in re.finditer(simple_pattern, content, re.MULTILINE):
        config[match.group(1)] = parse_simple_value(match.group(2))

    return config


def resolve_rule_path(config, cli_rule_path):
    candidates = []
    if cli_rule_path:
        candidates.append(cli_rule_path)
    configured = config.get("RulePath")
    if configured:
        candidates.append(configured)
    candidates.append(os.path.join(repo_dir, "wafconf"))

    for path in candidates:
        path = os.path.abspath(path)
        if os.path.isdir(path):
            return path
    return os.path.abspath(candidates[-1])


def read_rule_file(rule_path, filename):
    filepath = os.path.join(rule_path, filename)
    rules, seen, duplicates = [], set(), 0
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line in seen:
                    duplicates += 1
                    continue
                seen.add(line)
                rules.append(line)
    return rules, duplicates


def build_rule_sets(rule_path, rule_types):
    rule_sets, duplicate_total = {}, 0
    for rule_type in rule_types:
        rules, duplicates = read_rule_file(rule_path, rule_type)
        rule_sets[rule_type] = rules
        duplicate_total += duplicates
    return rule_sets, duplicate_total


def parse_args():
    parser = argparse.ArgumentParser(description="Initialize WAF config/rules into Redis.")
    parser.add_argument("--rule-path", help="Rule directory to load instead of config.lua RulePath.")
    parser.add_argument("--dry-run", action="store_true", help="Read config/rules and print stats without writing Redis.")
    return parser.parse_args()


def main():
    args = parse_args()
    config = read_config()
    rule_types = ["url", "args", "post", "cookie", "user-agent", "whiteurl", "cmd", "ssrf", "pathtraversal", "sensitivefile", "webshell"]
    rule_path = resolve_rule_path(config, args.rule_path)
    rule_sets, duplicate_total = build_rule_sets(rule_path, rule_types)

    redis_host = config.get("redis_host", "127.0.0.1")
    redis_port = int(config.get("redis_port", 6379))
    redis_db = int(config.get("redis_db", 0))
    redis_username = config.get("redis_username")
    if redis_username == "nil":
        redis_username = None
    redis_password = config.get("redis_password")
    if redis_password == "nil":
        redis_password = None

    print("Initializing WAF Redis data...")
    print(f"Redis: {redis_host}:{redis_port}/{redis_db}")
    print(f"Rule path: {rule_path}")
    print(f"Duplicate rules skipped: {duplicate_total}")

    if args.dry_run:
        print("\n=== Dry run rule stats ===")
        for rule_type in rule_types:
            print(f"[OK] {rule_type}: {len(rule_sets[rule_type])} rules")
        print("Dry run complete; Redis was not modified.")
        return

    try:
        import redis
    except ImportError:
        print("Error: redis package is not installed")
        print("Please run: pip install redis")
        sys.exit(1)

    try:
        r = redis.Redis(
            host=redis_host,
            port=redis_port,
            db=redis_db,
            username=redis_username,
            password=redis_password,
            decode_responses=True,
        )
        r.ping()
    except Exception as e:
        print(f"Error: unable to connect Redis - {e}")
        return

    config_key = "waf:config"
    r.delete(config_key)
    config_fields = {
        "attacklog": config.get("attacklog", "on"),
        "logdir": config.get("logdir", "/usr/local/openresty/nginx/logs/hack/"),
        "UrlDeny": config.get("UrlDeny", "on"),
        "Redirect": config.get("Redirect", "on"),
        "CookieMatch": config.get("CookieMatch", "on"),
        "postMatch": config.get("postMatch", "on"),
        "whiteModule": config.get("whiteModule", "on"),
        "CCDeny": config.get("CCDeny", "on"),
        "CCrate": config.get("CCrate", "10/60"),
        "CCBanTime": config.get("CCBanTime", "3600"),
        "html": config.get("html", ""),
        "CmdMatch": config.get("CmdMatch", "on"),
        "SSRFCheck": config.get("SSRFCheck", "on"),
        "PathTraversalCheck": config.get("PathTraversalCheck", "on"),
        "SensitiveFileCheck": config.get("SensitiveFileCheck", "on"),
        "WebshellCheck": config.get("WebshellCheck", "on"),
        "ResponseFilter": config.get("ResponseFilter", "off"),
        "decode_depth": config.get("decode_depth", "2"),
        "static_skip": config.get("static_skip", "light"),
    }
    for key, value in config_fields.items():
        r.hset(config_key, key, str(value))
    print("[OK] config initialized")

    for rule_type in rule_types:
        key = f"waf:rules:{rule_type}"
        r.delete(key)
        rules = rule_sets[rule_type]
        if rules:
            r.sadd(key, *rules)
        print(f"[OK] {rule_type} rules initialized ({len(rules)} rules)")

    whitelist_key = "waf:ip:whitelist"
    r.delete(whitelist_key)
    ip_whitelist = config.get("ipWhitelist", ["127.0.0.1"])
    if ip_whitelist:
        r.sadd(whitelist_key, *ip_whitelist)
    print(f"[OK] IP whitelist initialized ({len(ip_whitelist)} IPs)")

    blocklist_key = "waf:ip:blocklist"
    r.delete(blocklist_key)
    ip_blocklist = config.get("ipBlocklist", ["1.0.0.1"])
    if ip_blocklist:
        r.sadd(blocklist_key, *ip_blocklist)
    print(f"[OK] IP blocklist initialized ({len(ip_blocklist)} IPs)")

    r.set("waf:version:config", "1")
    r.set("waf:version:rules", "1")
    r.set("waf:version:ip", "1")
    print("[OK] versions initialized")
    print("\nRedis initialization complete.")


if __name__ == "__main__":
    main()
