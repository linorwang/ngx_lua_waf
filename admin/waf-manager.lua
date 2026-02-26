#!/usr/bin/env lua
-- WAF 管理脚本 - 方便管理 Redis 中的 WAF 配置和规则

local script_path = debug.getinfo(1, "S").source:sub(2)
local script_dir = script_path:match("(.*/)") or ""
package.path = script_dir .. "../?.lua;" .. package.path

local config = require "config"
local socket = require "socket"

local function redis_cmd(host, port, db, cmd, ...)
    local sock = socket.tcp(); sock:settimeout(1000)
    local ok, err = sock:connect(host, port)
    if not ok then return nil, err end
    if config.redis_password then
        sock:send(config.redis_username and "AUTH "..config.redis_username.." "..config.redis_password.."\r\n" or "AUTH "..config.redis_password.."\r\n")
        local res = sock:receive("*l")
        if not res or res:sub(1,1) == '-' then sock:close(); return nil, "auth failed" end
    end
    if db and db ~= 0 then
        sock:send("SELECT "..db.."\r\n")
        local res = sock:receive("*l")
        if not res or res:sub(1,1) == '-' then sock:close(); return nil, "select db failed" end
    end
    local args = {cmd, ...}; local req = "*"..#args.."\r\n"
    for _, arg in ipairs(args) do req = req.."$"..#tostring(arg).."\r\n"..tostring(arg).."\r\n" end
    sock:send(req)
    
    local function read_response()
        local line = sock:receive("*l")
        if not line then return nil end
        local t = line:sub(1,1)
        if t == '-' then return nil, line:sub(2)
        elseif t == '+' then return line:sub(2)
        elseif t == ':' then return tonumber(line:sub(2))
        elseif t == '$' then
            local len = tonumber(line:sub(2))
            if len == -1 then return nil end
            local data = sock:receive(len)
            sock:receive(2)
            return data
        elseif t == '*' then
            local cnt = tonumber(line:sub(2))
            local res = {}
            for i=1,cnt do
                local v, e = read_response()
                if e then return nil, e end
                res[i] = v
            end
            return res
        end
        return line
    end
    
    local res, err = read_response()
    sock:close()
    return res, err
end

local h = config.redis_host or "127.0.0.1"
local p = config.redis_port or 6379
local db = config.redis_db or 0

local function print_help()
    print([[
OpenResty + Redis WAF 管理工具

用法: lua waf-manager.lua <命令> [参数]

命令列表:

配置管理:
  config list                    - 列出所有配置
  config get <key>              - 获取配置项
  config set <key> <value>      - 设置配置项

规则管理:
  rule list <type>               - 列出指定类型的规则 (url/args/post/cookie/user-agent/whiteurl)
  rule add <type> <rule>         - 添加规则
  rule del <type> <rule>         - 删除规则

IP 管理:
  ip whitelist list              - 列出白名单 IP
  ip whitelist add <ip>          - 添加白名单 IP
  ip whitelist del <ip>          - 删除白名单 IP
  ip blocklist list               - 列出黑名单 IP
  ip blocklist add <ip>           - 添加黑名单 IP
  ip blocklist del <ip>           - 删除黑名单 IP

CC 防护:
  cc status <ip> <uri>           - 查看 CC 计数
  cc reset <ip> <uri>            - 重置 CC 计数

其他:
  version                        - 查看所有版本号
  flush                          - 增加所有版本号（刷新缓存）
  info                           - 显示 WAF 信息

示例:
  lua waf-manager.lua config list
  lua waf-manager.lua config set attacklog on
  lua waf-manager.lua rule add url "evil\.php"
  lua waf-manager.lua ip whitelist add 192.168.1.100
]])
end

local function cmd_config_list()
    local res, err = redis_cmd(h, p, db, "HGETALL", "waf:config")
    if err then print("错误:", err); return end
    print("\n=== WAF 配置 ===")
    if not res or #res == 0 then
        print("(无配置)")
    else
        for i=1,#res,2 do
            print(string.format("  %-20s = %s", res[i], res[i+1]))
        end
    end
    print()
end

local function cmd_config_get(key)
    local res, err = redis_cmd(h, p, db, "HGET", "waf:config", key)
    if err then print("错误:", err); return end
    print(string.format("%s = %s", key, res or "(空)"))
end

local function cmd_config_set(key, value)
    local _, err = redis_cmd(h, p, db, "HSET", "waf:config", key, value)
    if err then print("错误:", err); return end
    redis_cmd(h, p, db, "INCR", "waf:version:config")
    print(string.format("已设置: %s = %s", key, value))
    print("(配置版本已增加，缓存将自动刷新)")
end

local function cmd_rule_list(rule_type)
    local res, err = redis_cmd(h, p, db, "SMEMBERS", "waf:rules:"..rule_type)
    if err then print("错误:", err); return end
    print(string.format("\n=== %s 规则 (%d 条) ===", rule_type, res and #res or 0))
    if not res or #res == 0 then
        print("(无规则)")
    else
        for i, r in ipairs(res) do
            print(string.format("  %d. %s", i, r))
        end
    end
    print()
end

local function cmd_rule_add(rule_type, rule)
    local res, err = redis_cmd(h, p, db, "SADD", "waf:rules:"..rule_type, rule)
    if err then print("错误:", err); return end
    redis_cmd(h, p, db, "INCR", "waf:version:rules")
    if res == 1 then
        print(string.format("已添加规则: %s", rule))
    else
        print(string.format("规则已存在: %s", rule))
    end
    print("(规则版本已增加，缓存将自动刷新)")
end

local function cmd_rule_del(rule_type, rule)
    local res, err = redis_cmd(h, p, db, "SREM", "waf:rules:"..rule_type, rule)
    if err then print("错误:", err); return end
    redis_cmd(h, p, db, "INCR", "waf:version:rules")
    if res == 1 then
        print(string.format("已删除规则: %s", rule))
    else
        print(string.format("规则不存在: %s", rule))
    end
    print("(规则版本已增加，缓存将自动刷新)")
end

local function cmd_ip_list(list_type)
    local res, err = redis_cmd(h, p, db, "SMEMBERS", "waf:ip:"..list_type)
    if err then print("错误:", err); return end
    local name = list_type == "whitelist" and "白名单" or "黑名单"
    print(string.format("\n=== IP %s (%d 条) ===", name, res and #res or 0))
    if not res or #res == 0 then
        print("(无 IP)")
    else
        for i, ip in ipairs(res) do
            print(string.format("  %d. %s", i, ip))
        end
    end
    print()
end

local function cmd_ip_add(list_type, ip)
    local res, err = redis_cmd(h, p, db, "SADD", "waf:ip:"..list_type, ip)
    if err then print("错误:", err); return end
    redis_cmd(h, p, db, "INCR", "waf:version:ip")
    local name = list_type == "whitelist" and "白名单" or "黑名单"
    if res == 1 then
        print(string.format("已添加到%s: %s", name, ip))
    else
        print(string.format("%s已存在: %s", name, ip))
    end
    print("(IP 版本已增加，缓存将自动刷新)")
end

local function cmd_ip_del(list_type, ip)
    local res, err = redis_cmd(h, p, db, "SREM", "waf:ip:"..list_type, ip)
    if err then print("错误:", err); return end
    redis_cmd(h, p, db, "INCR", "waf:version:ip")
    local name = list_type == "whitelist" and "白名单" or "黑名单"
    if res == 1 then
        print(string.format("已从%s删除: %s", name, ip))
    else
        print(string.format("%s不存在: %s", name, ip))
    end
    print("(IP 版本已增加，缓存将自动刷新)")
end

local function cmd_cc_status(ip, uri)
    local res, err = redis_cmd(h, p, db, "GET", "waf:cc:"..ip..":"..uri)
    if err then print("错误:", err); return end
    print(string.format("CC 计数 - IP: %s, URI: %s", ip, uri))
    print(string.format("当前计数: %s", res or "0"))
end

local function cmd_cc_reset(ip, uri)
    local _, err = redis_cmd(h, p, db, "DEL", "waf:cc:"..ip..":"..uri)
    if err then print("错误:", err); return end
    print(string.format("已重置 CC 计数 - IP: %s, URI: %s", ip, uri))
end

local function cmd_version()
    local v1, _ = redis_cmd(h, p, db, "GET", "waf:version:config")
    local v2, _ = redis_cmd(h, p, db, "GET", "waf:version:rules")
    local v3, _ = redis_cmd(h, p, db, "GET", "waf:version:ip")
    print("\n=== 版本号 ===")
    print(string.format("  config: %s", v1 or "0"))
    print(string.format("  rules:  %s", v2 or "0"))
    print(string.format("  ip:     %s", v3 or "0"))
    print()
end

local function cmd_flush()
    redis_cmd(h, p, db, "INCR", "waf:version:config")
    redis_cmd(h, p, db, "INCR", "waf:version:rules")
    redis_cmd(h, p, db, "INCR", "waf:version:ip")
    print("已刷新所有版本号，本地缓存将在下次请求时更新")
end

local function cmd_info()
    print("\n" .. string.rep("=", 50))
    print("  OpenResty + Redis WAF 信息")
    print(string.rep("=", 50))
    print(string.format("\nRedis: %s:%d/%d", h, p, db))
    print(string.format("状态: %s", config.use_redis and "Redis 模式" or "文件模式"))
    cmd_version()
    cmd_config_list()
    local rule_types = {"url", "args", "post", "cookie", "user-agent", "whiteurl"}
    for _, t in ipairs(rule_types) do
        local cnt, _ = redis_cmd(h, p, db, "SCARD", "waf:rules:"..t)
        print(string.format("%-12s 规则: %d 条", t, cnt or 0))
    end
    local wl, _ = redis_cmd(h, p, db, "SCARD", "waf:ip:whitelist")
    local bl, _ = redis_cmd(h, p, db, "SCARD", "waf:ip:blocklist")
    print(string.format("\n白名单 IP: %d 条", wl or 0))
    print(string.format("黑名单 IP: %d 条", bl or 0))
    print("\n" .. string.rep("=", 50) .. "\n")
end

local cmd = arg[1]

if not cmd then
    print_help()
    os.exit(1)
end

if cmd == "config" then
    local sub = arg[2]
    if sub == "list" then
        cmd_config_list()
    elseif sub == "get" and arg[3] then
        cmd_config_get(arg[3])
    elseif sub == "set" and arg[3] and arg[4] then
        cmd_config_set(arg[3], arg[4])
    else
        print_help()
    end
elseif cmd == "rule" then
    local sub = arg[2]
    local rule_type = arg[3]
    local valid_types = {url=true, args=true, post=true, cookie=true, ["user-agent"]=true, whiteurl=true}
    if not rule_type or not valid_types[rule_type] then
        print("错误: 规则类型必须是 url/args/post/cookie/user-agent/whiteurl 之一")
        print_help()
    elseif sub == "list" then
        cmd_rule_list(rule_type)
    elseif sub == "add" and arg[4] then
        cmd_rule_add(rule_type, arg[4])
    elseif sub == "del" and arg[4] then
        cmd_rule_del(rule_type, arg[4])
    else
        print_help()
    end
elseif cmd == "ip" then
    local list_type = arg[2]
    local sub = arg[3]
    if list_type ~= "whitelist" and list_type ~= "blocklist" then
        print("错误: IP 列表类型必须是 whitelist 或 blocklist")
        print_help()
    elseif sub == "list" then
        cmd_ip_list(list_type)
    elseif sub == "add" and arg[4] then
        cmd_ip_add(list_type, arg[4])
    elseif sub == "del" and arg[4] then
        cmd_ip_del(list_type, arg[4])
    else
        print_help()
    end
elseif cmd == "cc" then
    local sub = arg[2]
    if sub == "status" and arg[3] and arg[4] then
        cmd_cc_status(arg[3], arg[4])
    elseif sub == "reset" and arg[3] and arg[4] then
        cmd_cc_reset(arg[3], arg[4])
    else
        print_help()
    end
elseif cmd == "version" then
    cmd_version()
elseif cmd == "flush" then
    cmd_flush()
elseif cmd == "info" then
    cmd_info()
else
    print_help()
end
