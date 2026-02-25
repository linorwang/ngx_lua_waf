#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
初始化 Redis 数据脚本（Python 版本）
依赖：pip install redis
"""

import sys
import os

# 添加项目根目录到 Python 路径
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(script_dir, '..'))

try:
    import redis
except ImportError:
    print("错误：未安装 redis 模块")
    print("请运行：pip install redis")
    sys.exit(1)

# 读取 config.lua 配置（简单解析）
def read_config():
    config = {}
    config_path = os.path.join(script_dir, '..', 'config.lua')
    with open(config_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('--') and '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip().rstrip(',')
                if value.startswith('"') or value.startswith("'"):
                    value = value[1:-1]
                config[key] = value
    return config

# 读取规则文件
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
    
    # Redis 连接
    redis_host = config.get('redis_host', '127.0.0.1')
    redis_port = int(config.get('redis_port', 6379))
    redis_username = config.get('redis_username')
    if redis_username == 'nil':
        redis_username = None
    redis_password = config.get('redis_password')
    if redis_password == 'nil':
        redis_password = None
    
    rule_path = config.get('RulePath', '/usr/local/nginx/conf/waf/wafconf/')
    
    print("正在初始化 Redis 数据...")
    print(f"Redis: {redis_host}:{redis_port}")
    
    try:
        r = redis.Redis(
            host=redis_host,
            port=redis_port,
            username=redis_username,
            password=redis_password,
            decode_responses=True
        )
        r.ping()
    except Exception as e:
        print(f"错误：无法连接 Redis - {e}")
        return
    
    # 初始化配置
    config_key = "waf:config"
    r.delete(config_key)
    r.hset(config_key, "attacklog", config.get('attacklog', 'on'))
    r.hset(config_key, "logdir", config.get('logdir', '/usr/local/nginx/logs/hack/'))
    r.hset(config_key, "UrlDeny", config.get('UrlDeny', 'on'))
    r.hset(config_key, "Redirect", config.get('Redirect', 'on'))
    r.hset(config_key, "CookieMatch", config.get('CookieMatch', 'on'))
    r.hset(config_key, "postMatch", config.get('postMatch', 'on'))
    r.hset(config_key, "whiteModule", config.get('whiteModule', 'on'))
    r.hset(config_key, "CCDeny", config.get('CCDeny', 'off'))
    r.hset(config_key, "CCrate", config.get('CCrate', '100/60'))
    r.hset(config_key, "html", config.get('html', ''))
    print("[OK] 配置已初始化")
    
    # 初始化规则
    rule_types = ["url", "args", "post", "cookie", "user-agent", "whiteurl"]
    for rule_type in rule_types:
        key = f"waf:rules:{rule_type}"
        r.delete(key)
        rules = read_rule_file(rule_path, rule_type)
        if rules:
            r.sadd(key, *rules)
        print(f"[OK] {rule_type} 规则已初始化 ({len(rules)} 条)")
    
    # 初始化 IP 白名单
    whitelist_key = "waf:ip:whitelist"
    r.delete(whitelist_key)
    ip_whitelist = ["127.0.0.1"]
    if ip_whitelist:
        r.sadd(whitelist_key, *ip_whitelist)
    print(f"[OK] IP 白名单已初始化 ({len(ip_whitelist)} 条)")
    
    # 初始化 IP 黑名单
    blocklist_key = "waf:ip:blocklist"
    r.delete(blocklist_key)
    ip_blocklist = ["1.0.0.1"]
    if ip_blocklist:
        r.sadd(blocklist_key, *ip_blocklist)
    print(f"[OK] IP 黑名单已初始化 ({len(ip_blocklist)} 条)")
    
    # 初始化版本号
    r.set("waf:version:config", "1")
    r.set("waf:version:rules", "1")
    r.set("waf:version:ip", "1")
    print("[OK] 版本号已初始化")
    
    print("\n✅ Redis 数据初始化完成！")

if __name__ == "__main__":
    main()
