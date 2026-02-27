#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
初始化 Redis 数据脚本（Python 版本）
依赖：pip install redis
"""

import sys
import os
import re

script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(script_dir, '..'))

try:
    import redis
except ImportError:
    print("错误：未安装 redis 模块")
    print("请运行：pip install redis")
    sys.exit(1)

def read_config():
    config = {}
    config_path = os.path.join(script_dir, '..', 'config.lua')
    
    with open(config_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 先移除所有注释
    # 移除多行注释 --[[ ... ]]
    content = re.sub(r'--\[\[.*?\]\]', '', content, flags=re.DOTALL)
    # 移除单行注释
    content = re.sub(r'--.*$', '', content, flags=re.MULTILINE)
    
    # 在 local _M = 之前截断，只解析前面的变量定义
    content = content.split('local _M =')[0]
    
    # 解析简单的 key = value 对
    def parse_simple_value(value_str):
        value_str = value_str.strip()
        if value_str == 'true':
            return True
        elif value_str == 'false':
            return False
        elif value_str == 'nil':
            return None
        elif value_str.startswith('"') or value_str.startswith("'"):
            return value_str[1:-1]
        else:
            # 数字，返回字符串
            return value_str
    
    # 解析数组
    def parse_array(value_str):
        items = []
        for item in re.findall(r'"([^"]+)"|\'([^\']+)\'', value_str):
            items.append(item[0] or item[1])
        return items
    
    # 先处理 html = [[ ... ]] 这种多行字符串（避免被简单值模式匹配）
    html_match = re.search(r'html\s*=\s*\[\[(.*?)\]\]', content, re.DOTALL)
    if html_match:
        config['html'] = html_match.group(1)
        # 从内容中移除 html 部分，避免被其他模式匹配
        content = re.sub(r'html\s*=\s*\[\[.*?\]\]', '', content, flags=re.DOTALL)
    
    # 再解析数组（带有 { ... } 的）
    array_pattern = r'^(\w+)\s*=\s*(\{.*?\})$'
    for match in re.finditer(array_pattern, content, re.DOTALL | re.MULTILINE):
        key = match.group(1)
        value_str = match.group(2)
        config[key] = parse_array(value_str)
    
    # 最后解析简单值
    simple_pattern = r'^(\w+)\s*=\s*([^={\n]+)$'
    for match in re.finditer(simple_pattern, content, re.MULTILINE):
        key = match.group(1)
        value_str = match.group(2)
        config[key] = parse_simple_value(value_str)
    
    return config

def read_rule_file(rule_path, filename):
    filepath = os.path.join(rule_path, filename)
    rules = []
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    rules.append(line)
    return rules

def main():
    config = read_config()
    
    redis_host = config.get('redis_host', '127.0.0.1')
    redis_port = int(config.get('redis_port', 6379))
    redis_db = int(config.get('redis_db', 0))
    redis_username = config.get('redis_username')
    if redis_username == 'nil':
        redis_username = None
    redis_password = config.get('redis_password')
    if redis_password == 'nil':
        redis_password = None
    
    rule_path = config.get('RulePath', '/usr/local/openresty/nginx/conf/waf/wafconf/')
    
    print("正在初始化 Redis 数据...")
    print(f"Redis: {redis_host}:{redis_port}/{redis_db}")
    
    try:
        r = redis.Redis(
            host=redis_host,
            port=redis_port,
            db=redis_db,
            username=redis_username,
            password=redis_password,
            decode_responses=True
        )
        r.ping()
    except Exception as e:
        print(f"错误：无法连接 Redis - {e}")
        return
    
    config_key = "waf:config"
    r.delete(config_key)
    r.hset(config_key, "attacklog", config.get('attacklog', 'on'))
    r.hset(config_key, "logdir", config.get('logdir', '/usr/local/openresty/nginx/logs/hack/'))
    r.hset(config_key, "UrlDeny", config.get('UrlDeny', 'on'))
    r.hset(config_key, "Redirect", config.get('Redirect', 'on'))
    r.hset(config_key, "CookieMatch", config.get('CookieMatch', 'on'))
    r.hset(config_key, "postMatch", config.get('postMatch', 'on'))
    r.hset(config_key, "whiteModule", config.get('whiteModule', 'on'))
    r.hset(config_key, "CCDeny", config.get('CCDeny', 'on'))
    r.hset(config_key, "CCrate", config.get('CCrate', '10/60'))
    r.hset(config_key, "CCBanTime", config.get('CCBanTime', '3600'))
    r.hset(config_key, "html", config.get('html', ''))
    print("[OK] 配置已初始化")
    
    rule_types = ["url", "args", "post", "cookie", "user-agent", "whiteurl"]
    for rule_type in rule_types:
        key = f"waf:rules:{rule_type}"
        r.delete(key)
        rules = read_rule_file(rule_path, rule_type)
        if rules:
            r.sadd(key, *rules)
        print(f"[OK] {rule_type} 规则已初始化 ({len(rules)} 条)")
    
    whitelist_key = "waf:ip:whitelist"
    r.delete(whitelist_key)
    ip_whitelist = config.get('ipWhitelist', ["127.0.0.1"])
    if ip_whitelist:
        r.sadd(whitelist_key, *ip_whitelist)
    print(f"[OK] IP 白名单已初始化 ({len(ip_whitelist)} 条)")
    print(f"   IP: {', '.join(ip_whitelist)}")
    
    blocklist_key = "waf:ip:blocklist"
    r.delete(blocklist_key)
    ip_blocklist = config.get('ipBlocklist', ["1.0.0.1"])
    print(f"准备添加 IP 黑名单，共 {len(ip_blocklist)} 条:")
    for i, ip in enumerate(ip_blocklist, 1):
        print(f"   {i}. {ip}")
    if ip_blocklist:
        r.sadd(blocklist_key, *ip_blocklist)
    print(f"[OK] IP 黑名单已初始化 ({len(ip_blocklist)} 条)")
    
    # 验证数据
    print("\n=== 验证数据 ===")
    verify_blocklist = r.smembers(blocklist_key)
    print(f"✓ 验证：Redis 中的 IP 黑名单有 {len(verify_blocklist)} 条:")
    for i, ip in enumerate(sorted(verify_blocklist), 1):
        print(f"  {i}. {ip}")
    
    r.set("waf:version:config", "1")
    r.set("waf:version:rules", "1")
    r.set("waf:version:ip", "1")
    print("[OK] 版本号已初始化")
    
    print("\n✅ Redis 数据初始化完成！")

if __name__ == "__main__":
    main()
