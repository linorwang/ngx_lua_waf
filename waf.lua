local config = require "config"

-- 模块预加载（不执行任何网络操作）
local waf_redis, waf_cache = nil, nil

local function ensure_modules_loaded()
    if not waf_redis then
        waf_redis = require "redis"
    end
    if not waf_cache then
        waf_cache = require "cache"
    end
end

local match, ngxmatch, unescape, get_headers = string.match, ngx.re.match, ngx.unescape_uri, ngx.req.get_headers

local logpath, rulepath = config.logdir, config.RulePath
local runtime_config, rules_cache = {}, {url={}, args={}, post={}, cookie={}, ["user-agent"]={}, whiteurl={}, cmd={}, ssrf={}, pathtraversal={}, sensitivefile={}, webshell={}}
local ip_whitelist_map, ip_blocklist_map = {}, {}

-- Worker级缓存标记
local worker_cache = {
    last_load_time = 0,
    load_interval = config.cache_ttl or 60
}

-- 静态资源后缀列表（跳过检测）
local static_extensions = {
    js = true, css = true, png = true, jpg = true, jpeg = true,
    gif = true, ico = true, svg = true, woff = true, woff2 = true,
    ttf = true, eot = true, otf = true, webp = true, mp4 = true,
    webm = true, mp3 = true, wav = true, flac = true, aac = true,
    pdf = true, doc = true, docx = true, xls = true, xlsx = true,
    ppt = true, pptx = true, zip = true, rar = true, tar = true,
    gz = true, ["7z"] = true
}

-- CC封禁本地缓存（减少Redis查询）
local cc_ban_cache = {
    ip_map = {},
    last_sync_time = 0,
    sync_interval = 10  -- 每10秒同步一次
}

local function optionIsOn(opt) return opt == "on" end

-- 检查是否为静态资源请求
local function is_static_request()
    local uri = ngx.var.uri
    if not uri then return false end
    local ext = uri:match("%.(%w+)$")
    return ext and static_extensions[ext:lower()] == true
end

-- 检查是否需要重新加载配置
local function should_reload()
    local now = ngx.time()
    if now - worker_cache.last_load_time < worker_cache.load_interval then
        return false
    end
    worker_cache.last_load_time = now
    return true
end

-- 检查版本并加载（带缓存机制）
local function check_version_and_load(cache_type, load_redis, load_cache, set_cache)
    ensure_modules_loaded()
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
    ensure_modules_loaded()
    local c = check_version_and_load(
        "config",
        function() return waf_redis.get_all_config() end,
        function() return waf_cache.get_all_config() end,
        function(x) waf_cache.set_all_config(x) end
    )
    runtime_config = c or {
        attacklog=config.attacklog, logdir=config.logdir, UrlDeny=config.UrlDeny,
        Redirect=config.Redirect, CookieMatch=config.CookieMatch, postMatch=config.postMatch,
        whiteModule=config.whiteModule, CCDeny=config.CCDeny, CCrate=config.CCrate, 
        CCBanTime=config.CCBanTime, html=config.html,
        CmdMatch=config.CmdMatch, SSRFCheck=config.SSRFCheck,
        PathTraversalCheck=config.PathTraversalCheck, SensitiveFileCheck=config.SensitiveFileCheck,
        WebshellCheck=config.WebshellCheck, ResponseFilter=config.ResponseFilter
    }
end

local function load_rules(rule_type)
    ensure_modules_loaded()
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
    ensure_modules_loaded()
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
    local line = ua and (ip.." ["..t.."] \""..method.." "..sn..url.."\" \""..(data or "-").."\"  \""..ua.."\" \""..tag.."\"\n")
                    or (ip.." ["..t.."] \""..method.." "..sn..url.."\" \""..(data or "-").."\" - \""..tag.."\"\n")
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
                log('GET', ngx.var.request_uri, data, r); say_html(); return true
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

local function cmd()
    if not optionIsOn(get_config("CmdMatch", config.CmdMatch)) then return false end
    local rules = load_rules("cmd")
    if not rules then return false end
    
    local args_table = ngx.req.get_uri_args()
    for _, r in ipairs(rules) do
        for k, v in pairs(args_table) do
            local data
            if type(v) == 'table' then
                local t={}; for _, x in ipairs(v) do t[#t+1] = x==true and "" or x end; data=table.concat(t, " ")
            else data=v end
            if data and type(data)~="boolean" and r~="" and ngxmatch(unescape(data), r, "isjo") then
                log('GET', ngx.var.request_uri, data, r); say_html(); return true
            end
        end
    end
    return false
end

local function pathtraversal()
    if not optionIsOn(get_config("PathTraversalCheck", config.PathTraversalCheck)) then return false end
    local rules = load_rules("pathtraversal")
    if rules then for _, r in ipairs(rules) do if r~="" and ngxmatch(ngx.var.request_uri, r, "isjo") then
        log('GET', ngx.var.request_uri, "-", r); say_html(); return true
    end end end
    return false
end

local function sensitivefile()
    if not optionIsOn(get_config("SensitiveFileCheck", config.SensitiveFileCheck)) then return false end
    local rules = load_rules("sensitivefile")
    if rules then for _, r in ipairs(rules) do if r~="" and ngxmatch(ngx.var.request_uri, r, "isjo") then
        log('GET', ngx.var.request_uri, "-", r); say_html(); return true
    end end end
    return false
end

local function ssrf()
    if not optionIsOn(get_config("SSRFCheck", config.SSRFCheck)) then return false end
    local rules = load_rules("ssrf")
    if not rules then return false end
    
    local args_table = ngx.req.get_uri_args()
    for _, r in ipairs(rules) do
        for k, v in pairs(args_table) do
            local data
            if type(v) == 'table' then
                local t={}; for _, x in ipairs(v) do t[#t+1] = x==true and "" or x end; data=table.concat(t, " ")
            else data=v end
            if data and type(data)~="boolean" and r~="" and ngxmatch(unescape(data), r, "isjo") then
                log('GET', ngx.var.request_uri, data, r); say_html(); return true
            end
        end
    end
    return false
end

local function webshell()
    if not optionIsOn(get_config("WebshellCheck", config.WebshellCheck)) then return false end
    local rules = load_rules("webshell")
    if not rules then return false end
    
    local args_table = ngx.req.get_uri_args()
    for _, r in ipairs(rules) do
        for k, v in pairs(args_table) do
            local data
            if type(v) == 'table' then
                local t={}; for _, x in ipairs(v) do t[#t+1] = x==true and "" or x end; data=table.concat(t, " ")
            else data=v end
            if data and type(data)~="boolean" and r~="" and ngxmatch(unescape(data), r, "isjo") then
                log('GET', ngx.var.request_uri, data, r); say_html(); return true
            end
        end
    end
    return false
end

local function post_cmd(body_data)
    if not optionIsOn(get_config("CmdMatch", config.CmdMatch)) then return false end
    local rules = load_rules("cmd")
    if rules then for _, r in ipairs(rules) do if r~="" and body_data~="" and ngxmatch(unescape(body_data), r, "isjo") then
        log('POST', ngx.var.request_uri, body_data, r); say_html(); return true
    end end end
    return false
end

local function post_ssrf(body_data)
    if not optionIsOn(get_config("SSRFCheck", config.SSRFCheck)) then return false end
    local rules = load_rules("ssrf")
    if rules then for _, r in ipairs(rules) do if r~="" and body_data~="" and ngxmatch(unescape(body_data), r, "isjo") then
        log('POST', ngx.var.request_uri, body_data, r); say_html(); return true
    end end end
    return false
end

local function post_webshell(body_data)
    if not optionIsOn(get_config("WebshellCheck", config.WebshellCheck)) then return false end
    local rules = load_rules("webshell")
    if rules then for _, r in ipairs(rules) do if r~="" and body_data~="" and ngxmatch(unescape(body_data), r, "isjo") then
        log('POST', ngx.var.request_uri, body_data, r); say_html(); return true
    end end end
    return false
end

local function denycc()
    ensure_modules_loaded()
    if not optionIsOn(get_config("CCDeny", config.CCDeny)) then return false end
    local uri, rate, ip = ngx.var.uri, get_config("CCrate", config.CCrate), getClientIp()
    local ban_time = tonumber(get_config("CCBanTime", config.CCBanTime or 3600))
    
    -- 先检查本地封禁缓存
    local now = ngx.time()
    if cc_ban_cache.ip_map[ip] and cc_ban_cache.ip_map[ip] > now then
        -- 返回优雅的CC拦截页面，保持503状态码
        ngx.header.content_type="text/html"
        ngx.status=ngx.HTTP_SERVICE_UNAVAILABLE
        ngx.say(get_config("html", config.html))
        ngx.exit(ngx.status)
        return true
    end
    
    -- 定期同步封禁状态到Redis
    if now - cc_ban_cache.last_sync_time > cc_ban_cache.sync_interval then
        cc_ban_cache.last_sync_time = now
        -- 清理过期本地缓存
        for k, v in pairs(cc_ban_cache.ip_map) do
            if v <= now then
                cc_ban_cache.ip_map[k] = nil
            end
        end
        -- 检查Redis是否有新的封禁
        local banned = waf_redis.cc_ban_check(ip)
        if banned then
            cc_ban_cache.ip_map[ip] = now + ban_time
            -- 返回优雅的CC拦截页面，保持503状态码
            ngx.header.content_type="text/html"
            ngx.status=ngx.HTTP_SERVICE_UNAVAILABLE
            ngx.say(get_config("html", config.html))
            ngx.exit(ngx.status)
            return true
        end
    end
    
    local cnt, sec = tonumber(rate:match('(.*)/')), tonumber(rate:match('/(.*)'))
    -- 优先使用本地共享内存计数
    local limit, token = ngx.shared.limit, ip..uri
    local req = limit:get(token)
    if req then 
        if req >= cnt then 
            -- 超过阈值，设置本地和Redis封禁
            cc_ban_cache.ip_map[ip] = now + ban_time
            waf_redis.cc_ban_set(ip, ban_time)
            -- 返回优雅的CC拦截页面，保持503状态码
            ngx.header.content_type="text/html"
            ngx.status=ngx.HTTP_SERVICE_UNAVAILABLE
            ngx.say(get_config("html", config.html))
            ngx.exit(ngx.status)
            return true 
        else 
            limit:incr(token,1) 
        end
    else 
        limit:set(token,1,sec) 
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

local function load_all()
    -- 只有需要时才重新加载配置
    if not should_reload() then
        return
    end
    load_config()
    for _, t in ipairs{"url","args","post","cookie","user-agent","whiteurl","cmd","ssrf","pathtraversal","sensitivefile","webshell"} do load_rules(t) end
    load_ip_list("whitelist", config.ipWhitelist)
    load_ip_list("blocklist", config.ipBlocklist)
end

-- WAF 主函数（导出供调用）
local function run_waf()
    local ok, err = pcall(function()
        -- 1. 先检测是否是静态资源，直接跳过
        if is_static_request() then
            return
        end

        load_all()

        if whiteip() then return end
        if blockip() then return end
        if denycc() then return end
        if whiteurl() then return end
        if url() then return end
        if sensitivefile() then return end
        if pathtraversal() then return end
        if args() then return end
        if cmd() then return end
        if ssrf() then return end
        if webshell() then return end
        if ua() then return end
        if cookie() then return end

        local method, boundary, ext = ngx.req.get_method(), get_boundary(), nil
        if method == "POST" then
            ngx.req.read_body()
            local body_data = ngx.req.get_body_data()
            if body_data then
                if body(body_data) then return end
                if post_cmd(body_data) then return end
                if post_ssrf(body_data) then return end
                if post_webshell(body_data) then return end
                if boundary then
                    for e in body_data:gmatch('filename=".-%.(.-)"') do ext = e; break end
                else
                    ext = body_data:match('name=".-"%s*%s*%s*(.-)$')
                end
                if ext and fileExtCheck(ext) then return end
            else
                local f = ngx.req.get_body_file()
                if f then
                    local fd = io.open(f, "r")
                    if fd then local d = fd:read("*a"); fd:close(); if d and body(d) then return end end
                end
            end
        end
    end)

    if not ok then
        ngx.log(ngx.ERR, "[WAF] Error: ", err)
    end
end

-- 导出模块
local _M = {}
_M.run = run_waf
return _M
