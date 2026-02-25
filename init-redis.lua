local config = require "config"

-- 如果不使用 Redis 版本，回退到原始 init.lua
if not config.use_redis then
    dofile(ngx.config.prefix() .. "conf/waf/init.lua.original")
    return
end

local match = string.match
local ngxmatch = ngx.re.match
local unescape = ngx.unescape_uri
local get_headers = ngx.req.get_headers
local optionIsOn = function (options) return options == "on" and true or false end

-- 加载 Redis 和缓存模块
local waf_redis = require "redis"
local waf_cache = require "cache"

-- 全局变量
logpath = config.logdir
rulepath = config.RulePath

-- 运行时配置（从 Redis 加载）
local runtime_config = {}

-- 从 Redis 加载配置（带缓存）
local function load_config()
    -- 检查版本
    local cached_version = waf_cache.get_version("config")
    local redis_version, err = waf_redis.get_version("config")
    
    if cached_version and redis_version and cached_version == redis_version then
        -- 版本相同，使用缓存
        local cached_config = waf_cache.get_all_config()
        if cached_config then
            runtime_config = cached_config
            return
        end
    end
    
    -- 从 Redis 加载
    local configs, err = waf_redis.get_all_config()
    if configs then
        runtime_config = configs
        waf_cache.set_all_config(configs)
        waf_cache.set_version("config", redis_version or "0")
    else
        -- Redis 不可用，使用 config.lua 中的默认值
        runtime_config = {
            attacklog = config.attacklog,
            logdir = config.logdir,
            UrlDeny = config.UrlDeny,
            Redirect = config.Redirect,
            CookieMatch = config.CookieMatch,
            postMatch = config.postMatch,
            whiteModule = config.whiteModule,
            CCDeny = config.CCDeny,
            CCrate = config.CCrate,
            html = config.html
        }
    end
end

-- 规则缓存
local rules_cache = {
    url = {},
    args = {},
    post = {},
    cookie = {},
    ["user-agent"] = {},
    whiteurl = {}
}

-- 从 Redis 加载规则（带缓存）
local function load_rules(rule_type)
    -- 检查版本
    local cached_version = waf_cache.get_version("rules")
    local redis_version, err = waf_redis.get_version("rules")
    
    if cached_version and redis_version and cached_version == redis_version then
        -- 版本相同，使用缓存
        local cached_rules = waf_cache.get_rules(rule_type)
        if cached_rules then
            rules_cache[rule_type] = cached_rules
            return cached_rules
        end
    end
    
    -- 从 Redis 加载
    local rules, err = waf_redis.get_rules(rule_type)
    if rules and #rules > 0 then
        rules_cache[rule_type] = rules
        waf_cache.set_rules(rule_type, rules)
        waf_cache.set_version("rules", redis_version or "0")
    else
        -- Redis 不可用或为空，从文件加载（兼容旧版本）
        local file = io.open(rulepath .. rule_type, "r")
        if file then
            local t = {}
            for line in file:lines() do
                table.insert(t, line)
            end
            file:close()
            rules_cache[rule_type] = t
        end
    end
    
    return rules_cache[rule_type]
end

-- IP 名单缓存
local ip_whitelist_cache = {}
local ip_blocklist_cache = {}

-- 从 Redis 加载 IP 白名单（带缓存）
local function load_ip_whitelist()
    local cached_version = waf_cache.get_version("ip")
    local redis_version, err = waf_redis.get_version("ip")
    
    if cached_version and redis_version and cached_version == redis_version then
        local cached_ips = waf_cache.get_ip_whitelist()
        if cached_ips then
            ip_whitelist_cache = cached_ips
            return cached_ips
        end
    end
    
    local ips, err = waf_redis.get_ip_whitelist()
    if ips and #ips > 0 then
        ip_whitelist_cache = ips
        waf_cache.set_ip_whitelist(ips)
        waf_cache.set_version("ip", redis_version or "0")
    else
        ip_whitelist_cache = config.ipWhitelist
    end
    
    return ip_whitelist_cache
end

-- 从 Redis 加载 IP 黑名单（带缓存）
local function load_ip_blocklist()
    local cached_version = waf_cache.get_version("ip")
    local redis_version, err = waf_redis.get_version("ip")
    
    if cached_version and redis_version and cached_version == redis_version then
        local cached_ips = waf_cache.get_ip_blocklist()
        if cached_ips then
            ip_blocklist_cache = cached_ips
            return cached_ips
        end
    end
    
    local ips, err = waf_redis.get_ip_blocklist()
    if ips and #ips > 0 then
        ip_blocklist_cache = ips
        waf_cache.set_ip_blocklist(ips)
        waf_cache.set_version("ip", redis_version or "0")
    else
        ip_blocklist_cache = config.ipBlocklist
    end
    
    return ip_blocklist_cache
end

-- 获取配置值
local function get_config(key, default)
    return runtime_config[key] or default
end

-- 辅助函数
function getClientIp()
    IP = ngx.var.remote_addr 
    if IP == nil then
        IP = "unknown"
    end
    return IP
end

function write(logfile, msg)
    local fd = io.open(logfile, "ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end

function log(method, url, data, ruletag)
    local attacklog_enabled = optionIsOn(get_config("attacklog", config.attacklog))
    if attacklog_enabled then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local servername = ngx.var.server_name
        local time = ngx.localtime()
        local log_dir = get_config("logdir", config.logdir)
        if ua then
            line = realIp .. " [" .. time .. "] \"" .. method .. " " .. servername .. url .. "\" \"" .. data .. "\"  \"" .. ua .. "\" \"" .. ruletag .. "\"\n"
        else
            line = realIp .. " [" .. time .. "] \"" .. method .. " " .. servername .. url .. "\" \"" .. data .. "\" - \"" .. ruletag .. "\"\n"
        end
        local filename = log_dir .. '/' .. servername .. "_" .. ngx.today() .. "_sec.log"
        write(filename, line)
    end
end

function say_html()
    local redirect_enabled = optionIsOn(get_config("Redirect", config.Redirect))
    if redirect_enabled then
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(get_config("html", config.html))
        ngx.exit(ngx.status)
    end
end

function whiteurl()
    local white_check = optionIsOn(get_config("whiteModule", config.whiteModule))
    if white_check then
        local rules = load_rules("whiteurl")
        if rules then
            for _, rule in pairs(rules) do
                if ngxmatch(ngx.var.uri, rule, "isjo") then
                    return true 
                end
            end
        end
    end
    return false
end

function fileExtCheck(ext)
    local items = {}
    for _, v in ipairs(config.black_fileExt) do
        items[v] = true
    end
    ext = string.lower(ext)
    if ext then
        for rule in pairs(items) do
            if ngx.re.match(ext, rule, "isjo") then
                log('POST', ngx.var.request_uri, "-", "file attack with ext " .. ext)
                say_html()
            end
        end
    end
    return false
end

function args()
    local rules = load_rules("args")
    if rules then
        for _, rule in pairs(rules) do
            local args = ngx.req.get_uri_args()
            for key, val in pairs(args) do
                if type(val) == 'table' then
                    local t = {}
                    for k, v in pairs(val) do
                        if v == true then
                            v = ""
                        end
                        table.insert(t, v)
                    end
                    data = table.concat(t, " ")
                else
                    data = val
                end
                if data and type(data) ~= "boolean" and rule ~= "" and ngxmatch(unescape(data), rule, "isjo") then
                    log('GET', ngx.var.request_uri, "-", rule)
                    say_html()
                    return true
                end
            end
        end
    end
    return false
end

function url()
    local url_deny = optionIsOn(get_config("UrlDeny", config.UrlDeny))
    if url_deny then
        local rules = load_rules("url")
        if rules then
            for _, rule in pairs(rules) do
                if rule ~= "" and ngxmatch(ngx.var.request_uri, rule, "isjo") then
                    log('GET', ngx.var.request_uri, "-", rule)
                    say_html()
                    return true
                end
            end
        end
    end
    return false
end

function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        local rules = load_rules("user-agent")
        if rules then
            for _, rule in pairs(rules) do
                if rule ~= "" and ngxmatch(ua, rule, "isjo") then
                    log('UA', ngx.var.request_uri, "-", rule)
                    say_html()
                    return true
                end
            end
        end
    end
    return false
end

function body(data)
    local rules = load_rules("post")
    if rules then
        for _, rule in pairs(rules) do
            if rule ~= "" and data ~= "" and ngxmatch(unescape(data), rule, "isjo") then
                log('POST', ngx.var.request_uri, data, rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function cookie()
    local cookie_check = optionIsOn(get_config("CookieMatch", config.CookieMatch))
    local ck = ngx.var.http_cookie
    if cookie_check and ck then
        local rules = load_rules("cookie")
        if rules then
            for _, rule in pairs(rules) do
                if rule ~= "" and ngxmatch(ck, rule, "isjo") then
                    log('Cookie', ngx.var.request_uri, "-", rule)
                    say_html()
                    return true
                end
            end
        end
    end
    return false
end

function denycc()
    local cc_deny = optionIsOn(get_config("CCDeny", config.CCDeny))
    if cc_deny then
        local uri = ngx.var.uri
        local cc_rate = get_config("CCrate", config.CCrate)
        CCcount = tonumber(string.match(cc_rate, '(.*)/'))
        CCseconds = tonumber(string.match(cc_rate, '/(.*)'))
        local token = getClientIp() .. uri
        
        -- 使用 Redis 进行 CC 计数
        local count, err = waf_redis.cc_incr(getClientIp(), uri, CCseconds)
        if count then
            if count > CCcount then
                ngx.exit(503)
                return true
            end
        else
            -- Redis 不可用时回退到本地共享内存
            local limit = ngx.shared.limit
            local req, _ = limit:get(token)
            if req then
                if req > CCcount then
                    ngx.exit(503)
                    return true
                else
                    limit:incr(token, 1)
                end
            else
                limit:set(token, 1, CCseconds)
            end
        end
    end
    return false
end

function get_boundary()
    local header = get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end

    local m = match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end

    return match(header, ";%s*boundary=([^\",;]+)")
end

function whiteip()
    local whitelist = load_ip_whitelist()
    if whitelist and #whitelist > 0 then
        for _, ip in pairs(whitelist) do
            if getClientIp() == ip then
                return true
            end
        end
    end
    return false
end

function blockip()
    local blocklist = load_ip_blocklist()
    if blocklist and #blocklist > 0 then
        for _, ip in pairs(blocklist) do
            if getClientIp() == ip then
                ngx.exit(403)
                return true
            end
        end
    end
    return false
end

-- 初始化：预加载配置
load_config()
load_rules("url")
load_rules("args")
load_rules("post")
load_rules("cookie")
load_rules("user-agent")
load_rules("whiteurl")
load_ip_whitelist()
load_ip_blocklist()
