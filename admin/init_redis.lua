#!/usr/bin/env lua
-- 初始化 Redis 数据脚本

local script_path = debug.getinfo(1, "S").source:sub(2)
local script_dir = script_path:match("(.*/)") or ""
package.path = script_dir .. "../?.lua;" .. package.path

local config = require "config"

-- 简单的 Redis 客户端（用于命令行）
local redis = require "socket"

local function read_rule_file(filename)
    local file = io.open(config.RulePath .. filename, "r")
    if not file then
        return {}
    end
    local rules = {}
    for line in file:lines() do
        if line and line ~= "" then
            table.insert(rules, line)
        end
    end
    file:close()
    return rules
end

-- 使用 luasocket 实现简单的 Redis 通信
local function redis_cmd(host, port, cmd, ...)
    local sock = socket.tcp()
    sock:settimeout(1000)
    local ok, err = sock:connect(host, port)
    if not ok then
        return nil, err
    end
    
    if config.redis_password then
        if config.redis_username then
            -- Redis 6.0+ ACL: 用户名 + 密码
            sock:send("AUTH " .. config.redis_username .. " " .. config.redis_password .. "\r\n")
        else
            -- 只有密码（传统方式）
            sock:send("AUTH " .. config.redis_password .. "\r\n")
        end
        local res = sock:receive("*l")
        if not res or res:sub(1, 1) == '-' then
            sock:close()
            return nil, "auth failed"
        end
    end
    
    local args = {cmd, ...}
    local req = "*" .. #args .. "\r\n"
    for _, arg in ipairs(args) do
        req = req .. "$" .. #tostring(arg) .. "\r\n" .. tostring(arg) .. "\r\n"
    end
    
    sock:send(req)
    
    local line, err = sock:receive("*l")
    sock:close()
    
    if not line then
        return nil, err
    end
    
    if line:sub(1, 1) == '-' then
        return nil, line:sub(2)
    elseif line:sub(1, 1) == '+' then
        return line:sub(2)
    elseif line:sub(1, 1) == ':' then
        return tonumber(line:sub(2))
    elseif line:sub(1, 1) == '$' then
        local len = tonumber(line:sub(2))
        if len == -1 then
            return nil
        end
        local data, err = sock:receive(len + 2)
        return data:sub(1, -3)
    elseif line:sub(1, 1) == '*' then
        local count = tonumber(line:sub(2))
        local result = {}
        for i = 1, count do
            local l, err = sock:receive("*l")
            if l and l:sub(1, 1) == '$' then
                local len = tonumber(l:sub(2))
                if len == -1 then
                    table.insert(result, nil)
                else
                    local data, err = sock:receive(len + 2)
                    table.insert(result, data:sub(1, -3))
                end
            end
        end
        return result
    end
    
    return line
end

local function hset(host, port, key, field, value)
    return redis_cmd(host, port, "HSET", key, field, value)
end

local function del(host, port, key)
    return redis_cmd(host, port, "DEL", key)
end

local function sadd(host, port, key, ...)
    return redis_cmd(host, port, "SADD", key, ...)
end

local function set(host, port, key, value)
    return redis_cmd(host, port, "SET", key, value)
end

local host = config.redis_host or "127.0.0.1"
local port = config.redis_port or 6379

print("正在初始化 Redis 数据...")
print("Redis: " .. host .. ":" .. port)

-- 初始化配置
local config_key = "waf:config"
del(host, port, config_key)
hset(host, port, config_key, "attacklog", config.attacklog)
hset(host, port, config_key, "logdir", config.logdir)
hset(host, port, config_key, "UrlDeny", config.UrlDeny)
hset(host, port, config_key, "Redirect", config.Redirect)
hset(host, port, config_key, "CookieMatch", config.CookieMatch)
hset(host, port, config_key, "postMatch", config.postMatch)
hset(host, port, config_key, "whiteModule", config.whiteModule)
hset(host, port, config_key, "CCDeny", config.CCDeny)
hset(host, port, config_key, "CCrate", config.CCrate)
hset(host, port, config_key, "html", config.html)
print("[OK] 配置已初始化")

-- 初始化规则
local rule_types = {"url", "args", "post", "cookie", "user-agent", "whiteurl"}
for _, rule_type in ipairs(rule_types) do
    local key = "waf:rules:" .. rule_type
    del(host, port, key)
    local rules = read_rule_file(rule_type)
    if #rules > 0 then
        sadd(host, port, key, unpack(rules))
    end
    print("[OK] " .. rule_type .. " 规则已初始化 (" .. #rules .. " 条)")
end

-- 初始化 IP 白名单
local whitelist_key = "waf:ip:whitelist"
del(host, port, whitelist_key)
if #config.ipWhitelist > 0 then
    sadd(host, port, whitelist_key, unpack(config.ipWhitelist))
end
print("[OK] IP 白名单已初始化 (" .. #config.ipWhitelist .. " 条)")

-- 初始化 IP 黑名单
local blocklist_key = "waf:ip:blocklist"
del(host, port, blocklist_key)
if #config.ipBlocklist > 0 then
    sadd(host, port, blocklist_key, unpack(config.ipBlocklist))
end
print("[OK] IP 黑名单已初始化 (" .. #config.ipBlocklist .. " 条)")

-- 初始化版本号
set(host, port, "waf:version:config", "1")
set(host, port, "waf:version:rules", "1")
set(host, port, "waf:version:ip", "1")
print("[OK] 版本号已初始化")

print("\n✅ Redis 数据初始化完成！")
