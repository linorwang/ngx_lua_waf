local redis = require "resty.redis"
local config = require "config"

local _M = {}
local PREFIX = "waf:"

local function get_redis()
    local red = redis:new()
    red:set_timeout(config.redis_timeout or 1000)
    local ok, err = red:connect(config.redis_host or "127.0.0.1", config.redis_port or 6379)
    if not ok then ngx.log(ngx.ERR, "redis connect failed: ", err); return nil end
    if config.redis_password then
        ok, err = config.redis_username and red:auth(config.redis_username, config.redis_password) or red:auth(config.redis_password)
        if not ok then ngx.log(ngx.ERR, "redis auth failed: ", err); return nil end
    end
    if config.redis_db and config.redis_db ~= 0 then
        ok, err = red:select(config.redis_db)
        if not ok then ngx.log(ngx.ERR, "redis select db failed: ", err); return nil end
    end
    return red
end

local function close_redis(red)
    if not red then return end
    local ok, err = red:set_keepalive(config.redis_idle_timeout or 10000, config.redis_pool_size or 100)
    if not ok then ngx.log(ngx.ERR, "redis keepalive failed: ", err); red:close() end
end

local function build_key(...) return PREFIX .. table.concat({...}, ":") end

local function with_redis(callback)
    local red = get_redis()
    if not red then return nil end
    local res, err = callback(red)
    close_redis(red)
    return res, err
end

function _M.get_config(key) return with_redis(function(r) local v=r:hget(build_key("config"),key); return v~=ngx.null and v or nil end) end
function _M.get_all_config() return with_redis(function(r)
    local res=r:hgetall(build_key("config"))
    if not res or res==ngx.null then return nil end
    local c={}; for i=1,#res,2 do c[res[i]]=res[i+1] end; return c
end) end
function _M.set_config(k,v) return with_redis(function(r) local o=r:hset(build_key("config"),k,v); if o then r:incr(build_key("version","config")) end; return o end) end
function _M.get_rules(t) return with_redis(function(r) local res=r:smembers(build_key("rules",t)); return (res and res~=ngx.null) and res or {} end) end
function _M.add_rule(t,r) return with_redis(function(x) local o=x:sadd(build_key("rules",t),r); if o then x:incr(build_key("version","rules")) end; return o end) end
function _M.del_rule(t,r) return with_redis(function(x) local o=x:srem(build_key("rules",t),r); if o then x:incr(build_key("version","rules")) end; return o end) end
function _M.exists_rule(t,r) return with_redis(function(x) return x:sismember(build_key("rules",t),r)==1 end) end

local function ip_list_op(op, list_type, ip)
    return with_redis(function(r)
        local key = build_key("ip", list_type)
        if op == "get" then local res=r:smembers(key); return (res and res~=ngx.null) and res or {}
        elseif op == "add" then local o=r:sadd(key,ip); if o then r:incr(build_key("version","ip")) end; return o
        elseif op == "del" then local o=r:srem(key,ip); if o then r:incr(build_key("version","ip")) end; return o
        elseif op == "check" then return r:sismember(key,ip)==1 end
    end)
end

function _M.get_ip_whitelist() return ip_list_op("get","whitelist") end
function _M.add_ip_whitelist(ip) return ip_list_op("add","whitelist",ip) end
function _M.del_ip_whitelist(ip) return ip_list_op("del","whitelist",ip) end
function _M.check_ip_whitelist(ip) return ip_list_op("check","whitelist",ip) end
function _M.get_ip_blocklist() return ip_list_op("get","blocklist") end
function _M.add_ip_blocklist(ip) return ip_list_op("add","blocklist",ip) end
function _M.del_ip_blocklist(ip) return ip_list_op("del","blocklist",ip) end
function _M.check_ip_blocklist(ip) return ip_list_op("check","blocklist",ip) end

function _M.cc_incr(ip,uri,sec) return with_redis(function(r)
    local k=build_key("cc",ip,uri); r:init_pipeline(); r:incr(k); r:expire(k,sec)
    local res=r:commit_pipeline(); return res and res[1] or nil
end) end
function _M.cc_get(ip,uri) return with_redis(function(r) local v=r:get(build_key("cc",ip,uri)); return v~=ngx.null and (tonumber(v) or 0) or 0 end) end
function _M.get_version(t) return with_redis(function(r) local v=r:get(build_key("version",t)); return v~=ngx.null and v or "0" end) end
function _M.init_version(t) return with_redis(function(r) r:setnx(build_key("version",t),"0"); return true end) end
function _M.init_rules(t, rules) return with_redis(function(r)
    local k=build_key("rules",t); r:del(k)
    if #rules>0 then r:init_pipeline(); for _,x in ipairs(rules) do if x and x~="" then r:sadd(k,x) end end; r:commit_pipeline() end
    r:incr(build_key("version","rules")); return true
end) end
local function init_ip_list(t,ips) return with_redis(function(r)
    local k=build_key("ip",t); r:del(k)
    if #ips>0 then r:init_pipeline(); for _,x in ipairs(ips) do if x and x~="" then r:sadd(k,x) end end; r:commit_pipeline() end
    r:incr(build_key("version","ip")); return true
end) end
function _M.init_ip_whitelist(ips) return init_ip_list("whitelist",ips) end
function _M.init_ip_blocklist(ips) return init_ip_list("blocklist",ips) end
function _M.init_config(cfgs) return with_redis(function(r)
    local k=build_key("config"); r:del(k)
    if cfgs and next(cfgs) then for kk,vv in pairs(cfgs) do if vv then r:hset(k,kk,vv) end end end
    r:incr(build_key("version","config")); return true
end) end

return _M
