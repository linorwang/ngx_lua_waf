local waf_cache = ngx.shared.waf_cache
local config = require "config"

local _M = {}
local PREFIX = "waf_cache:"

local function get_ttl() return config.cache_ttl or 5 end
local function is_cache_enabled() return config.enable_cache ~= false end
local function build_key(...) return PREFIX .. table.concat({...}, ":") end

function _M.get(key)
    if not is_cache_enabled() then return nil end
    local v, e = waf_cache:get(build_key(key))
    if e then ngx.log(ngx.ERR, "cache get failed: ", e) end
    return v
end

function _M.set(key, value, ttl)
    if not is_cache_enabled() then return true end
    local ok, e, f = waf_cache:set(build_key(key), value, ttl or get_ttl())
    if e then ngx.log(ngx.ERR, "cache set failed: ", e); return false end
    if f then ngx.log(ngx.WARN, "cache full") end
    return true
end

function _M.del(key) waf_cache:delete(build_key(key)); return true end
function _M.get_version(t) return _M.get("version:"..t) end
function _M.set_version(t, v) return _M.set("version:"..t, v, get_ttl()) end

function _M.get_all_config()
    local s = _M.get("config:all")
    if not s then return nil end
    local c = {}; for k, v in string.gmatch(s, "([^|]+)=([^|]*)|") do c[k]=v end; return c
end

function _M.set_all_config(cfgs)
    local t = {}; for k, v in pairs(cfgs) do t[#t+1] = k.."="..tostring(v).."|" end
    return _M.set("config:all", table.concat(t))
end

local function deserialize_list(s)
    if not s then return nil end
    local t = {}; for item in string.gmatch(s, "[^\n]+") do t[#t+1] = item end; return t
end

local function serialize_list(list) return table.concat(list, "\n") end

function _M.get_rules(t) return deserialize_list(_M.get("rules:"..t)) end
function _M.set_rules(t, rules) return _M.set("rules:"..t, serialize_list(rules)) end
function _M.get_ip_whitelist() return deserialize_list(_M.get("ip:whitelist")) end
function _M.set_ip_whitelist(ips) return _M.set("ip:whitelist", serialize_list(ips)) end
function _M.get_ip_blocklist() return deserialize_list(_M.get("ip:blocklist")) end
function _M.set_ip_blocklist(ips) return _M.set("ip:blocklist", serialize_list(ips)) end

local function check_ip_in_list(cache_key, ip)
    local list = deserialize_list(_M.get(cache_key))
    if not list then return nil end
    for _, v in ipairs(list) do if v == ip then return true end end
    return false
end

function _M.check_ip_whitelist(ip) return check_ip_in_list("ip:whitelist", ip) end
function _M.check_ip_blocklist(ip) return check_ip_in_list("ip:blocklist", ip) end
function _M.flush_all() waf_cache:flush_all(); return true end

return _M
