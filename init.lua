local config = require "config"

if not config.use_redis then
    dofile(ngx.config.prefix() .. "conf/waf/init.lua.original")
    return
end

local match, ngxmatch, unescape, get_headers = string.match, ngx.re.match, ngx.unescape_uri, ngx.req.get_headers
local waf_redis, waf_cache = require "redis", require "cache"

local logpath, rulepath = config.logdir, config.RulePath
local runtime_config, rules_cache = {}, {url={}, args={}, post={}, cookie={}, ["user-agent"]={}, whiteurl={}}
local ip_whitelist_map, ip_blocklist_map = {}, {}

local function optionIsOn(opt) return opt == "on" end

local function check_version_and_load(cache_type, load_redis, load_cache, set_cache)
    local cv, rv = waf_cache.get_version(cache_type), waf_redis.get_version(cache_type)
    if cv and rv and cv == rv then
        local c = load_cache()
        if c then return c end
    end
    local d = load_redis()
    if d then set_cache(d); waf_cache.set_version(cache_type, rv or "0") end
    return d
end

local function load_config()
    local c = check_version_and_load(
        "config",
        function() return waf_redis.get_all_config() end,
        function() return waf_cache.get_all_config() end,
        function(x) waf_cache.set_all_config(x) end
    )
    runtime_config = c or {
        attacklog=config.attacklog, logdir=config.logdir, UrlDeny=config.UrlDeny,
        Redirect=config.Redirect, CookieMatch=config.CookieMatch, postMatch=config.postMatch,
        whiteModule=config.whiteModule, CCDeny=config.CCDeny, CCrate=config.CCrate, html=config.html
    }
end

local function load_rules(rule_type)
    local r = check_version_and_load(
        "rules",
        function() return waf_redis.get_rules(rule_type) end,
        function() return waf_cache.get_rules(rule_type) end,
        function(x) waf_cache.set_rules(rule_type, x) end
    )
    if r and #r > 0 then rules_cache[rule_type] = r
    else
        local f = io.open(rulepath..rule_type, "r")
        if f then local t={}; for l in f:lines() do t[#t+1]=l end; f:close(); rules_cache[rule_type]=t end
    end
    return rules_cache[rule_type]
end

local function load_ip_list(list_type, default)
    local list = check_version_and_load(
        "ip",
        function() return list_type=="whitelist" and waf_redis.get_ip_whitelist() or waf_redis.get_ip_blocklist() end,
        function() return list_type=="whitelist" and waf_cache.get_ip_whitelist() or waf_cache.get_ip_blocklist() end,
        function(x) 
            if list_type=="whitelist" then waf_cache.set_ip_whitelist(x) else waf_cache.set_ip_blocklist(x) end
        end
    )
    local map = list_type=="whitelist" and ip_whitelist_map or ip_blocklist_map
    for k in pairs(map) do map[k]=nil end
    for _, ip in ipairs(list or default) do map[ip]=true end
end

local function get_config(k, d) return runtime_config[k] or d end
local function getClientIp() return ngx.var.remote_addr or "unknown" end

local function write(file, msg)
    local fd = io.open(file, "ab")
    if fd then fd:write(msg); fd:flush(); fd:close() end
end

local function log(method, url, data, tag)
    if not optionIsOn(get_config("attacklog", config.attacklog)) then return end
    local ip, ua, sn, t, dir = getClientIp(), ngx.var.http_user_agent, ngx.var.server_name, ngx.localtime(), get_config("logdir", config.logdir)
    local line = ua and (ip.." ["..t.."] \""..method.." "..sn..url.."\" \""..data.."\"  \""..ua.."\" \""..tag.."\"\n")
                    or (ip.." ["..t.."] \""..method.." "..sn..url.."\" \""..data.."\" - \""..tag.."\"\n")
    write(dir..'/'..sn.."_"..ngx.today().."_sec.log", line)
end

local function say_html()
    if optionIsOn(get_config("Redirect", config.Redirect)) then
        ngx.header.content_type="text/html"; ngx.status=ngx.HTTP_FORBIDDEN; ngx.say(get_config("html", config.html)); ngx.exit(ngx.status)
    end
end

local function whiteurl()
    if not optionIsOn(get_config("whiteModule", config.whiteModule)) then return false end
    local rules = load_rules("whiteurl")
    if rules then for _, r in ipairs(rules) do if ngxmatch(ngx.var.uri, r, "isjo") then return true end end end
    return false
end

local function fileExtCheck(ext)
    if not ext then return false end
    ext = ext:lower()
    for _, v in ipairs(config.black_fileExt) do
        if ngx.re.match(ext, v, "isjo") then
            log('POST', ngx.var.request_uri, "-", "file attack with ext "..ext); say_html(); return true
        end
    end
    return false
end

local function args()
    local rules = load_rules("args")
    if not rules then return false end
    local args_table = ngx.req.get_uri_args()
    for _, r in ipairs(rules) do
        for k, v in pairs(args_table) do
            local data
            if type(v) == 'table' then
                local t={}; for _, x in ipairs(v) do t[#t+1] = x==true and "" or x end; data=table.concat(t, " ")
            else data=v end
            if data and type(data)~="boolean" and r~="" and ngxmatch(unescape(data), r, "isjo") then
                log('GET', ngx.var.request_uri, "-", r); say_html(); return true
            end
        end
    end
    return false
end

local function url()
    if not optionIsOn(get_config("UrlDeny", config.UrlDeny)) then return false end
    local rules = load_rules("url")
    if rules then for _, r in ipairs(rules) do if r~="" and ngxmatch(ngx.var.request_uri, r, "isjo") then
        log('GET', ngx.var.request_uri, "-", r); say_html(); return true
    end end end
    return false
end

local function ua()
    local ua_str = ngx.var.http_user_agent
    if not ua_str then return false end
    local rules = load_rules("user-agent")
    if rules then for _, r in ipairs(rules) do if r~="" and ngxmatch(ua_str, r, "isjo") then
        log('UA', ngx.var.request_uri, "-", r); say_html(); return true
    end end end
    return false
end

local function body(data)
    local rules = load_rules("post")
    if rules then for _, r in ipairs(rules) do if r~="" and data~="" and ngxmatch(unescape(data), r, "isjo") then
        log('POST', ngx.var.request_uri, data, r); say_html(); return true
    end end end
    return false
end

local function cookie()
    if not optionIsOn(get_config("CookieMatch", config.CookieMatch)) then return false end
    local ck = ngx.var.http_cookie
    if not ck then return false end
    local rules = load_rules("cookie")
    if rules then for _, r in ipairs(rules) do if r~="" and ngxmatch(ck, r, "isjo") then
        log('Cookie', ngx.var.request_uri, "-", r); say_html(); return true
    end end end
    return false
end

local function denycc()
    if not optionIsOn(get_config("CCDeny", config.CCDeny)) then return false end
    local uri, rate, ip = ngx.var.uri, get_config("CCrate", config.CCrate), getClientIp()
    local cnt, sec = tonumber(rate:match('(.*)/')), tonumber(rate:match('/(.*)'))
    local count = waf_redis.cc_incr(ip, uri, sec)
    if count then
        if count > cnt then ngx.exit(503); return true end
    else
        local limit, token = ngx.shared.limit, ip..uri
        local req = limit:get(token)
        if req then if req > cnt then ngx.exit(503); return true else limit:incr(token,1) end
        else limit:set(token,1,sec) end
    end
    return false
end

local function get_boundary()
    local h = get_headers()["content-type"]
    if not h then return nil end
    if type(h)=="table" then h=h[1] end
    local m = match(h, ';%s*boundary="([^"]+)"')
    return m or match(h, ';%s*boundary=([^",;]+)')
end

local function whiteip() return ip_whitelist_map[getClientIp()] == true end
local function blockip() if ip_blocklist_map[getClientIp()] then ngx.exit(403); return true end; return false end

_G.getClientIp, _G.write, _G.log, _G.say_html, _G.whiteurl, _G.fileExtCheck = getClientIp, write, log, say_html, whiteurl, fileExtCheck
_G.args, _G.url, _G.ua, _G.body, _G.cookie, _G.denycc, _G.get_boundary = args, url, ua, body, cookie, denycc, get_boundary
_G.whiteip, _G.blockip = whiteip, blockip

load_config()
for _, t in ipairs{"url","args","post","cookie","user-agent","whiteurl"} do load_rules(t) end
load_ip_list("whitelist", config.ipWhitelist)
load_ip_list("blocklist", config.ipBlocklist)
