local waf_cache = ngx.shared.waf_cache
local config = require "config"

local _M = {}

-- 缓存 Key 前缀
local PREFIX = "waf_cache:"

-- 获取缓存 TTL
local function get_ttl()
    return config.cache_ttl or 5
end

-- 检查是否启用缓存
local function is_cache_enabled()
    return config.enable_cache ~= false
end

-- 构建缓存 Key
local function build_key(...)
    local args = {...}
    return PREFIX .. table.concat(args, ":")
end

-- 获取缓存
function _M.get(key)
    if not is_cache_enabled() then
        return nil
    end
    
    local cache_key = build_key(key)
    local value, err = waf_cache:get(cache_key)
    
    if err then
        ngx.log(ngx.ERR, "failed to get cache: ", err)
        return nil
    end
    
    return value
end

-- 设置缓存
function _M.set(key, value, ttl)
    if not is_cache_enabled() then
        return true
    end
    
    local cache_key = build_key(key)
    local ttl = ttl or get_ttl()
    
    local ok, err, forcible = waf_cache:set(cache_key, value, ttl)
    
    if err then
        ngx.log(ngx.ERR, "failed to set cache: ", err)
        return false
    end
    
    if forcible then
        ngx.log(ngx.WARN, "cache is full, removed some items")
    end
    
    return true
end

-- 删除缓存
function _M.del(key)
    local cache_key = build_key(key)
    waf_cache:delete(cache_key)
    return true
end

-- 获取版本号缓存
function _M.get_version(version_type)
    return _M.get("version:" .. version_type)
end

-- 设置版本号缓存
function _M.set_version(version_type, version)
    return _M.set("version:" .. version_type, version, get_ttl())
end

-- 获取配置缓存
function _M.get_config(key)
    return _M.get("config:" .. key)
end

-- 设置配置缓存
function _M.set_config(key, value)
    return _M.set("config:" .. key, value)
end

-- 获取所有配置缓存
function _M.get_all_config()
    local config_str = _M.get("config:all")
    if not config_str then
        return nil
    end
    
    -- 简单的解析，实际项目可以用 cjson
    local configs = {}
    for k, v in string.gmatch(config_str, "([^|]+)=([^|]*)|") do
        configs[k] = v
    end
    return configs
end

-- 设置所有配置缓存
function _M.set_all_config(configs)
    local t = {}
    for k, v in pairs(configs) do
        table.insert(t, k .. "=" .. tostring(v) .. "|")
    end
    return _M.set("config:all", table.concat(t))
end

-- 获取规则缓存
function _M.get_rules(rule_type)
    local rules_str = _M.get("rules:" .. rule_type)
    if not rules_str then
        return nil
    end
    
    local rules = {}
    for rule in string.gmatch(rules_str, "[^\n]+") do
        table.insert(rules, rule)
    end
    return rules
end

-- 设置规则缓存
function _M.set_rules(rule_type, rules)
    return _M.set("rules:" .. rule_type, table.concat(rules, "\n"))
end

-- 获取 IP 白名单缓存
function _M.get_ip_whitelist()
    local ips_str = _M.get("ip:whitelist")
    if not ips_str then
        return nil
    end
    
    local ips = {}
    for ip in string.gmatch(ips_str, "[^\n]+") do
        table.insert(ips, ip)
    end
    return ips
end

-- 设置 IP 白名单缓存
function _M.set_ip_whitelist(ips)
    return _M.set("ip:whitelist", table.concat(ips, "\n"))
end

-- 获取 IP 黑名单缓存
function _M.get_ip_blocklist()
    local ips_str = _M.get("ip:blocklist")
    if not ips_str then
        return nil
    end
    
    local ips = {}
    for ip in string.gmatch(ips_str, "[^\n]+") do
        table.insert(ips, ip)
    end
    return ips
end

-- 设置 IP 黑名单缓存
function _M.set_ip_blocklist(ips)
    return _M.set("ip:blocklist", table.concat(ips, "\n"))
end

-- 检查 IP 是否在白名单缓存
function _M.check_ip_whitelist(ip)
    local whitelist = _M.get_ip_whitelist()
    if not whitelist then
        return nil
    end
    
    for _, v in ipairs(whitelist) do
        if v == ip then
            return true
        end
    end
    return false
end

-- 检查 IP 是否在黑名单缓存
function _M.check_ip_blocklist(ip)
    local blocklist = _M.get_ip_blocklist()
    if not blocklist then
        return nil
    end
    
    for _, v in ipairs(blocklist) do
        if v == ip then
            return true
        end
    end
    return false
end

-- 清除所有缓存
function _M.flush_all()
    waf_cache:flush_all()
    return true
end

return _M
