#!/usr/bin/env lua
local script_path = debug.getinfo(1, "S").source:sub(2)
local script_dir = script_path:match("(.*/)") or ""
package.path = script_dir .. "../?.lua;" .. package.path

local config = require "config"
local socket = require "socket"

local function read_rule_file(filename)
    local f = io.open(config.RulePath .. filename, "r")
    if not f then return {} end
    local t = {}; for line in f:lines() do if line and line ~= "" then t[#t+1] = line end end; f:close(); return t
end

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
    sock:send(req); local line = sock:receive("*l"); sock:close()
    if not line then return nil, err end
    if line:sub(1,1) == '-' then return nil, line:sub(2)
    elseif line:sub(1,1) == '+' then return line:sub(2)
    elseif line:sub(1,1) == ':' then return tonumber(line:sub(2))
    else return line end
end

local h = config.redis_host or "127.0.0.1"
local p = config.redis_port or 6379
local db = config.redis_db or 0

print("正在初始化 Redis 数据...")
print("Redis: " .. h .. ":" .. p .. "/" .. db)

local function hset(k,f,v) return redis_cmd(h,p,db,"HSET",k,f,v) end
local function del(k) return redis_cmd(h,p,db,"DEL",k) end
local function sadd(k,...) return redis_cmd(h,p,db,"SADD",k,...) end
local function set(k,v) return redis_cmd(h,p,db,"SET",k,v) end

local ck = "waf:config"; del(ck)
hset(ck,"attacklog",config.attacklog); hset(ck,"logdir",config.logdir); hset(ck,"UrlDeny",config.UrlDeny)
hset(ck,"Redirect",config.Redirect); hset(ck,"CookieMatch",config.CookieMatch); hset(ck,"postMatch",config.postMatch)
hset(ck,"whiteModule",config.whiteModule); hset(ck,"CCDeny",config.CCDeny); hset(ck,"CCrate",config.CCrate)
hset(ck,"html",config.html); print("[OK] 配置已初始化")

local rule_types = {"url","args","post","cookie","user-agent","whiteurl"}
for _, t in ipairs(rule_types) do
    local k = "waf:rules:"..t; del(k)
    local rules = read_rule_file(t)
    if #rules>0 then sadd(k,unpack(rules)) end
    print("[OK] "..t.." 规则已初始化 ("..#rules.." 条)")
end

local wk = "waf:ip:whitelist"; del(wk)
if #config.ipWhitelist>0 then sadd(wk,unpack(config.ipWhitelist)) end
print("[OK] IP 白名单已初始化 ("..#config.ipWhitelist.." 条)")

local bk = "waf:ip:blocklist"; del(bk)
if #config.ipBlocklist>0 then sadd(bk,unpack(config.ipBlocklist)) end
print("[OK] IP 黑名单已初始化 ("..#config.ipBlocklist.." 条)")

set("waf:version:config","1"); set("waf:version:rules","1"); set("waf:version:ip","1"); print("[OK] 版本号已初始化")
print("\n✅ Redis 数据初始化完成！")
