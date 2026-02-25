local redis = require "resty.redis"
local config = require "config"

local _M = {}
local mt = { __index = _M }

-- Redis Key 前缀
local PREFIX = "waf:"

-- 获取 Redis 连接
local function get_redis()
    local red = redis:new()
    red:set_timeout(config.redis_timeout or 1000)
    
    local ok, err = red:connect(config.redis_host or "127.0.0.1", config.redis_port or 6379)
    if not ok then
        ngx.log(ngx.ERR, "failed to connect to redis: ", err)
        return nil, err
    end
    
    if config.redis_password then
        local ok, err
        if config.redis_username then
            -- Redis 6.0+ ACL: 用户名 + 密码
            ok, err = red:auth(config.redis_username, config.redis_password)
        else
            -- 只有密码（传统方式）
            ok, err = red:auth(config.redis_password)
        end
        if not ok then
            ngx.log(ngx.ERR, "failed to authenticate: ", err)
            return nil, err
        end
    end
    
    return red
end

-- 归还 Redis 连接到连接池
local function close_redis(red)
    if not red then
        return
    end
    
    local pool_size = config.redis_pool_size or 100
    local idle_timeout = config.redis_idle_timeout or 10000
    
    local ok, err = red:set_keepalive(idle_timeout, pool_size)
    if not ok then
        ngx.log(ngx.ERR, "failed to set keepalive: ", err)
        red:close()
    end
end

-- 构建 Key
local function build_key(...)
    local args = {...}
    return PREFIX .. table.concat(args, ":")
end

-- 获取配置（Hash）
function _M.get_config(key)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local res, err = red:hget(build_key("config"), key)
    close_redis(red)
    
    if res == ngx.null then
        return nil
    end
    
    return res
end

-- 获取所有配置
function _M.get_all_config()
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local res, err = red:hgetall(build_key("config"))
    close_redis(red)
    
    if not res or res == ngx.null then
        return nil
    end
    
    local configs = {}
    for i = 1, #res, 2 do
        configs[res[i]] = res[i + 1]
    end
    
    return configs
end

-- 设置配置
function _M.set_config(key, value)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local ok, err = red:hset(build_key("config"), key, value)
    if ok then
        red:incr(build_key("version", "config"))
    end
    close_redis(red)
    
    return ok, err
end

-- 获取规则集合
function _M.get_rules(rule_type)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local res, err = red:smembers(build_key("rules", rule_type))
    close_redis(red)
    
    if not res or res == ngx.null then
        return {}
    end
    
    return res
end

-- 添加规则
function _M.add_rule(rule_type, rule)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local ok, err = red:sadd(build_key("rules", rule_type), rule)
    if ok then
        red:incr(build_key("version", "rules"))
    end
    close_redis(red)
    
    return ok, err
end

-- 删除规则
function _M.del_rule(rule_type, rule)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local ok, err = red:srem(build_key("rules", rule_type), rule)
    if ok then
        red:incr(build_key("version", "rules"))
    end
    close_redis(red)
    
    return ok, err
end

-- 检查规则是否存在
function _M.exists_rule(rule_type, rule)
    local red, err = get_redis()
    if not red then
        return false, err
    end
    
    local res, err = red:sismember(build_key("rules", rule_type), rule)
    close_redis(red)
    
    return res == 1, err
end

-- 获取 IP 白名单
function _M.get_ip_whitelist()
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local res, err = red:smembers(build_key("ip", "whitelist"))
    close_redis(red)
    
    if not res or res == ngx.null then
        return {}
    end
    
    return res
end

-- 添加 IP 到白名单
function _M.add_ip_whitelist(ip)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local ok, err = red:sadd(build_key("ip", "whitelist"), ip)
    if ok then
        red:incr(build_key("version", "ip"))
    end
    close_redis(red)
    
    return ok, err
end

-- 从白名单删除 IP
function _M.del_ip_whitelist(ip)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local ok, err = red:srem(build_key("ip", "whitelist"), ip)
    if ok then
        red:incr(build_key("version", "ip"))
    end
    close_redis(red)
    
    return ok, err
end

-- 检查 IP 是否在白名单
function _M.check_ip_whitelist(ip)
    local red, err = get_redis()
    if not red then
        return false, err
    end
    
    local res, err = red:sismember(build_key("ip", "whitelist"), ip)
    close_redis(red)
    
    return res == 1, err
end

-- 获取 IP 黑名单
function _M.get_ip_blocklist()
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local res, err = red:smembers(build_key("ip", "blocklist"))
    close_redis(red)
    
    if not res or res == ngx.null then
        return {}
    end
    
    return res
end

-- 添加 IP 到黑名单
function _M.add_ip_blocklist(ip)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local ok, err = red:sadd(build_key("ip", "blocklist"), ip)
    if ok then
        red:incr(build_key("version", "ip"))
    end
    close_redis(red)
    
    return ok, err
end

-- 从黑名单删除 IP
function _M.del_ip_blocklist(ip)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local ok, err = red:srem(build_key("ip", "blocklist"), ip)
    if ok then
        red:incr(build_key("version", "ip"))
    end
    close_redis(red)
    
    return ok, err
end

-- 检查 IP 是否在黑名单
function _M.check_ip_blocklist(ip)
    local red, err = get_redis()
    if not red then
        return false, err
    end
    
    local res, err = red:sismember(build_key("ip", "blocklist"), ip)
    close_redis(red)
    
    return res == 1, err
end

-- CC 防护：增加计数
function _M.cc_incr(ip, uri, seconds)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local key = build_key("cc", ip, uri)
    red:init_pipeline()
    red:incr(key)
    red:expire(key, seconds)
    local results, err = red:commit_pipeline()
    
    close_redis(red)
    
    if not results then
        return nil, err
    end
    
    return results[1]
end

-- CC 防护：获取计数
function _M.cc_get(ip, uri)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local key = build_key("cc", ip, uri)
    local res, err = red:get(key)
    close_redis(red)
    
    if res == ngx.null then
        return 0
    end
    
    return tonumber(res) or 0
end

-- 获取版本号
function _M.get_version(version_type)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local res, err = red:get(build_key("version", version_type))
    close_redis(red)
    
    if res == ngx.null then
        return "0"
    end
    
    return res
end

-- 初始化版本号
function _M.init_version(version_type)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local key = build_key("version", version_type)
    red:setnx(key, "0")
    close_redis(red)
    
    return true
end

-- 批量初始化规则
function _M.init_rules(rule_type, rules)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local key = build_key("rules", rule_type)
    red:del(key)
    
    if #rules > 0 then
        red:init_pipeline()
        for _, rule in ipairs(rules) do
            if rule and rule ~= "" then
                red:sadd(key, rule)
            end
        end
        red:commit_pipeline()
    end
    
    red:incr(build_key("version", "rules"))
    close_redis(red)
    
    return true
end

-- 批量初始化 IP 白名单
function _M.init_ip_whitelist(ips)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local key = build_key("ip", "whitelist")
    red:del(key)
    
    if #ips > 0 then
        red:init_pipeline()
        for _, ip in ipairs(ips) do
            if ip and ip ~= "" then
                red:sadd(key, ip)
            end
        end
        red:commit_pipeline()
    end
    
    red:incr(build_key("version", "ip"))
    close_redis(red)
    
    return true
end

-- 批量初始化 IP 黑名单
function _M.init_ip_blocklist(ips)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local key = build_key("ip", "blocklist")
    red:del(key)
    
    if #ips > 0 then
        red:init_pipeline()
        for _, ip in ipairs(ips) do
            if ip and ip ~= "" then
                red:sadd(key, ip)
            end
        end
        red:commit_pipeline()
    end
    
    red:incr(build_key("version", "ip"))
    close_redis(red)
    
    return true
end

-- 批量初始化配置
function _M.init_config(configs)
    local red, err = get_redis()
    if not red then
        return nil, err
    end
    
    local key = build_key("config")
    red:del(key)
    
    if configs and next(configs) then
        for k, v in pairs(configs) do
            if v then
                red:hset(key, k, v)
            end
        end
    end
    
    red:incr(build_key("version", "config"))
    close_redis(red)
    
    return true
end

return _M
