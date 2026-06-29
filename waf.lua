local config = require "config"

-- 模块预加载（不执行任何网络操作）
local waf_redis, waf_cache = nil, nil

local function ensure_cache_loaded()
    if config.enable_cache == false then return nil end
    if not waf_cache then
        local ok, mod = pcall(require, "cache")
        if ok then
            waf_cache = mod
        else
            ngx.log(ngx.ERR, "[WAF] cache module load failed: ", mod)
        end
    end
    return waf_cache
end

local function ensure_redis_loaded()
    if config.use_redis == false then return nil end
    if not waf_redis then
        local ok, mod = pcall(require, "redis")
        if ok then
            waf_redis = mod
        else
            ngx.log(ngx.ERR, "[WAF] redis module load failed: ", mod)
        end
    end
    return waf_redis
end

local function ensure_modules_loaded()
    ensure_cache_loaded()
    ensure_redis_loaded()
end

local match, ngxmatch, unescape, get_headers = string.match, ngx.re.match, ngx.unescape_uri, ngx.req.get_headers

local logpath, rulepath = config.logdir, config.RulePath
local module_source = debug.getinfo(1, "S").source
local module_dir = module_source and module_source:sub(1, 1) == "@" and module_source:match("@(.+[\\/])[^\\/]+$") or ""
local fallback_rulepath = module_dir ~= "" and (module_dir.."wafconf/") or "wafconf/"
local runtime_config, rules_cache = {}, {url={}, args={}, post={}, cookie={}, ["user-agent"]={}, whiteurl={}, cmd={}, ssrf={}, pathtraversal={}, sensitivefile={}, webshell={}}
local ip_whitelist_map, ip_blocklist_map = {}, {}

-- Worker级缓存标记
local worker_cache = {
    last_load_time = 0,
    load_interval = config.cache_ttl or 60,
    ip_cache_version = nil,
    last_ip_version_check_time = 0,
    ip_version_check_interval = config.ip_cache_check_interval or 1
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
    last_sync_by_ip = {},
    sync_interval = 10,
    last_cleanup_time = 0
}

local log_dir_attempted, shared_dicts_checked = {}, false
local lfs_mod, lfs_checked = nil, false

local function optionIsOn(opt) return opt == "on" end

local function safe_decode(data)
    if data == nil then return "" end
    if type(data) ~= "string" then return data end
    local depth = tonumber(runtime_config.decode_depth or config.decode_depth) or 2
    if depth < 0 then depth = 0 end
    local decoded = data
    for _ = 1, depth do
        local ok, next_decoded = pcall(unescape, decoded)
        if not ok then
            ngx.log(ngx.ERR, "[WAF] uri decode failed: ", next_decoded)
            return decoded
        end
        if not next_decoded or next_decoded == decoded then
            return decoded
        end
        decoded = next_decoded
    end
    return decoded
end

local function regex_is_too_complex(rule)
    if type(rule) ~= "string" then return true end
    local max_len = tonumber(runtime_config.maxRegexLength or config.maxRegexLength or 512) or 512
    if max_len > 0 and #rule > max_len then return true end
    if optionIsOn(runtime_config.rejectUnsafeRegex or config.rejectUnsafeRegex) then
        if rule:find("%([^)]-[*+][^)]-%)%s*[*+{]") then return true end
        if rule:find("%([^)]-{[^)]-%)%s*[*+{]") then return true end
    end
    return false
end

local function rule_allowed(rule, tag)
    if not regex_is_too_complex(rule) then return true end
    ngx.log(ngx.ERR, "[WAF] skip unsafe regex", tag and (" ["..tag.."]") or "", ": ", rule)
    return false
end

local function safe_match(subject, rule, tag)
    if subject == nil or rule == nil or rule == "" then return false end
    if not rule_allowed(rule, tag) then return false end
    if type(subject) ~= "string" then subject = tostring(subject) end
    local ok, res, err = pcall(ngxmatch, subject, rule, "isjo")
    if not ok then
        ngx.log(ngx.ERR, "[WAF] regex match failed", tag and (" ["..tag.."]") or "", ": ", res, " rule=", rule)
        return false
    end
    if err then
        ngx.log(ngx.ERR, "[WAF] invalid regex", tag and (" ["..tag.."]") or "", ": ", err, " rule=", rule)
        return false
    end
    return res ~= nil
end

-- 检查是否为静态资源请求
local function is_static_request()
    local uri = ngx.var.uri or ngx.var.request_uri
    if not uri then return false end
    uri = uri:gsub("[?#].*$", "")
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
    local cv, rv
    if waf_cache then cv = waf_cache.get_version(cache_type) end
    if waf_redis then rv = waf_redis.get_version(cache_type) end
    if cv and rv and cv == rv then
        local c = load_cache()
        if c then return c end
    end
    if waf_redis then
        local d = load_redis()
        if d then
            if waf_cache then set_cache(d); waf_cache.set_version(cache_type, rv or "0") end
            return d
        end
    end
    local cached = waf_cache and load_cache() or nil
    if not cached then
        ngx.log(ngx.WARN, "[WAF] ", cache_type, " not loaded from Redis/cache; falling back to local defaults")
    end
    return cached
end

local function local_config()
    return {
        attacklog=config.attacklog, logdir=config.logdir, UrlDeny=config.UrlDeny,
        Redirect=config.Redirect, CookieMatch=config.CookieMatch, postMatch=config.postMatch,
        whiteModule=config.whiteModule, CCDeny=config.CCDeny, CCrate=config.CCrate,
        CCBanTime=config.CCBanTime, CCScope=config.CCScope,
        CCCleanupInterval=config.CCCleanupInterval, html=config.html,
        CmdMatch=config.CmdMatch, SSRFCheck=config.SSRFCheck,
        PathTraversalCheck=config.PathTraversalCheck, SensitiveFileCheck=config.SensitiveFileCheck,
        WebshellCheck=config.WebshellCheck, ResponseFilter=config.ResponseFilter,
        securityHeaders=config.securityHeaders, contentSecurityPolicy=config.contentSecurityPolicy,
        decode_depth=config.decode_depth, static_skip=config.static_skip,
        maxRegexLength=config.maxRegexLength, rejectUnsafeRegex=config.rejectUnsafeRegex,
        realIpHeaders=config.realIpHeaders, trustedProxyIps=config.trustedProxyIps,
        bodyInspectMethods=config.bodyInspectMethods,
        maxRequestBodySize=config.maxRequestBodySize, alertEnabled=config.alertEnabled,
        alertThreshold=config.alertThreshold, alertWindow=config.alertWindow,
        reloadToken=config.reloadToken, RuleParams=config.RuleParams
    }
end

local function filter_rules(rule_type, rules)
    local filtered = {}
    for _, rule in ipairs(rules or {}) do
        if rule and rule ~= "" and rule_allowed(rule, rule_type) then
            filtered[#filtered + 1] = rule
        end
    end
    return filtered
end

local valid_rule_params = {
    post = true, webshell = true, pathtraversal = true,
    cmd = true, ssrf = true, sensitivefile = true
}

local function normalize_rule_param_list(value, default, field_name)
    local list = {}
    local function add(item)
        item = type(item) == "string" and item or tostring(item or "")
        if item ~= "" and valid_rule_params[item] then
            list[#list + 1] = item
        elseif item ~= "" then
            ngx.log(ngx.ERR, "[WAF] invalid ", field_name, " item ignored: ", item)
        end
    end

    if type(value) == "table" then
        for _, item in ipairs(value) do add(item) end
    elseif type(value) == "string" then
        for item in value:gmatch("[^,%s]+") do add(item) end
    elseif value ~= nil then
        ngx.log(ngx.ERR, "[WAF] invalid ", field_name, " config, fallback to default: ", tostring(value))
    end

    if #list == 0 then
        for _, item in ipairs(default or {"post"}) do add(item) end
    end
    return list
end

local function validate_runtime_config(c)
    local defaults = local_config()
    c = c or {}
    for k, v in pairs(defaults) do
        if c[k] == nil or c[k] == "" then c[k] = v end
    end

    if type(c.CCrate) ~= "string" or not c.CCrate:match("^%s*%d+%s*/%s*%d+%s*$") then
        ngx.log(ngx.ERR, "[WAF] invalid CCrate config, fallback to default: ", tostring(c.CCrate))
        c.CCrate = defaults.CCrate
    end

    local decode_depth = tonumber(c.decode_depth)
    if not decode_depth or decode_depth < 0 or decode_depth > 10 then
        ngx.log(ngx.ERR, "[WAF] invalid decode_depth config, fallback to default: ", tostring(c.decode_depth))
        c.decode_depth = defaults.decode_depth
    end

    local ban_time = tonumber(c.CCBanTime)
    if not ban_time or ban_time <= 0 then
        ngx.log(ngx.ERR, "[WAF] invalid CCBanTime config, fallback to default: ", tostring(c.CCBanTime))
        c.CCBanTime = defaults.CCBanTime
    end

    local max_regex_length = tonumber(c.maxRegexLength)
    if not max_regex_length or max_regex_length < 64 then
        ngx.log(ngx.ERR, "[WAF] invalid maxRegexLength config, fallback to default: ", tostring(c.maxRegexLength))
        c.maxRegexLength = defaults.maxRegexLength
    end

    local max_body_size = tonumber(c.maxRequestBodySize)
    if not max_body_size or max_body_size < 0 then
        ngx.log(ngx.ERR, "[WAF] invalid maxRequestBodySize config, fallback to default: ", tostring(c.maxRequestBodySize))
        c.maxRequestBodySize = defaults.maxRequestBodySize
    end

    local alert_threshold = tonumber(c.alertThreshold)
    if not alert_threshold or alert_threshold < 1 then
        ngx.log(ngx.ERR, "[WAF] invalid alertThreshold config, fallback to default: ", tostring(c.alertThreshold))
        c.alertThreshold = defaults.alertThreshold
    end

    local alert_window = tonumber(c.alertWindow)
    if not alert_window or alert_window < 1 then
        ngx.log(ngx.ERR, "[WAF] invalid alertWindow config, fallback to default: ", tostring(c.alertWindow))
        c.alertWindow = defaults.alertWindow
    end

    if c.static_skip ~= "light" and c.static_skip ~= "off" then
        ngx.log(ngx.ERR, "[WAF] invalid static_skip config, fallback to default: ", tostring(c.static_skip))
        c.static_skip = defaults.static_skip
    end

    local default_rule_params = type(defaults.RuleParams) == "table" and defaults.RuleParams or {post = {"post"}}
    local rule_params = type(c.RuleParams) == "table" and c.RuleParams or {}
    if c.RuleParams ~= nil and type(c.RuleParams) ~= "table" then
        ngx.log(ngx.ERR, "[WAF] invalid RuleParams config, fallback to default: ", tostring(c.RuleParams))
    end
    c.RuleParams = {
        post = normalize_rule_param_list(rule_params.post, default_rule_params.post, "RuleParams.post")
    }

    return c
end

local function load_local_rules(rule_type)
    local f = io.open(rulepath..rule_type, "r")
    if not f and fallback_rulepath ~= rulepath then
        f = io.open(fallback_rulepath..rule_type, "r")
    end
    if f then
        local t, seen = {}, {}
        for l in f:lines() do
            if l ~= "" and not seen[l] then
                t[#t+1] = l
                seen[l] = true
            end
        end
        f:close()
        rules_cache[rule_type] = filter_rules(rule_type, t)
    end
    return rules_cache[rule_type]
end

local function load_config()
    if config.use_redis == false then
        runtime_config = validate_runtime_config(local_config())
        return
    end
    ensure_modules_loaded()
    local c = check_version_and_load(
        "config",
        function() return waf_redis.get_all_config() end,
        function() return waf_cache.get_all_config() end,
        function(x) waf_cache.set_all_config(x) end
    )
    runtime_config = validate_runtime_config((c and next(c)) and c or local_config())
end

local function load_rules(rule_type)
    if config.use_redis == false then
        return load_local_rules(rule_type)
    end
    ensure_modules_loaded()
    local r = check_version_and_load(
        "rules",
        function() return waf_redis.get_rules(rule_type) end,
        function() return waf_cache.get_rules(rule_type) end,
        function(x) waf_cache.set_rules(rule_type, x) end
    )
    if r and #r > 0 then rules_cache[rule_type] = filter_rules(rule_type, r)
    else
        ngx.log(ngx.WARN, "[WAF] rules ", rule_type, " not loaded from Redis/cache; falling back to local file")
        load_local_rules(rule_type)
    end
    return rules_cache[rule_type]
end

local function load_ip_list(list_type, default)
    ensure_modules_loaded()
    local list, loaded_from_redis
    if list_type=="whitelist" then
        if waf_redis then list = waf_redis.get_ip_whitelist() end
        loaded_from_redis = list ~= nil
        if loaded_from_redis then
            if waf_cache then waf_cache.set_ip_whitelist(list) end
        elseif waf_cache then
            list = waf_cache.get_ip_whitelist()
        end
    else
        if waf_redis then list = waf_redis.get_ip_blocklist() end
        loaded_from_redis = list ~= nil
        if loaded_from_redis then
            if waf_cache then waf_cache.set_ip_blocklist(list) end
        elseif waf_cache then
            list = waf_cache.get_ip_blocklist()
        end
    end
    if not list then
        ngx.log(ngx.WARN, "[WAF] ip ", list_type, " not loaded from Redis/cache; falling back to local defaults")
    end
    if not list and worker_cache.ip_cache_version ~= nil then
        return false, false
    end
    local map = list_type=="whitelist" and ip_whitelist_map or ip_blocklist_map
    for k in pairs(map) do map[k]=nil end
    for _, ip in ipairs(list or default or {}) do if ip and ip~="" then map[ip]=true end end
    return true, loaded_from_redis
end

local function load_ip_lists_if_changed()
    if config.use_redis == false then
        if worker_cache.ip_cache_version == "local" then return end
        local wl, bl = ip_whitelist_map, ip_blocklist_map
        for k in pairs(wl) do wl[k]=nil end
        for k in pairs(bl) do bl[k]=nil end
        for _, ip in ipairs(config.ipWhitelist or {}) do if ip and ip~="" then wl[ip]=true end end
        for _, ip in ipairs(config.ipBlocklist or {}) do if ip and ip~="" then bl[ip]=true end end
        worker_cache.ip_cache_version = "local"
        return
    end
    ensure_modules_loaded()
    local now = ngx.time()
    if worker_cache.ip_cache_version ~= nil
        and now - worker_cache.last_ip_version_check_time < worker_cache.ip_version_check_interval then
        return
    end
    worker_cache.last_ip_version_check_time = now

    local redis_version = waf_redis and waf_redis.get_version("ip") or nil
    local cache_version = waf_cache and waf_cache.get_version("ip") or nil
    local next_version = redis_version or cache_version
    if next_version and worker_cache.ip_cache_version == next_version then
        return
    end
    if not next_version and worker_cache.ip_cache_version ~= nil then
        return
    end

    local whitelist_loaded, whitelist_from_redis = load_ip_list("whitelist", config.ipWhitelist)
    local blocklist_loaded, blocklist_from_redis = load_ip_list("blocklist", config.ipBlocklist)
    if not whitelist_loaded and not blocklist_loaded then
        return
    end

    if redis_version and whitelist_from_redis and blocklist_from_redis then
        if waf_cache then waf_cache.set_version("ip", redis_version) end
        worker_cache.ip_cache_version = redis_version
    elseif redis_version then
        worker_cache.ip_cache_version = cache_version or worker_cache.ip_cache_version or "local"
    else
        worker_cache.ip_cache_version = next_version or "local"
    end
end

local function get_config(k, d) return runtime_config[k] or d end

local function config_list(value)
    local list = {}
    if type(value) == "table" then
        for _, item in ipairs(value) do
            if item ~= nil and item ~= "" then list[#list + 1] = tostring(item) end
        end
    elseif type(value) == "string" then
        for item in value:gmatch("[^,%s]+") do
            if item ~= "" then list[#list + 1] = item end
        end
    end
    return list
end

local function trim(s)
    return type(s) == "string" and (s:match("^%s*(.-)%s*$") or "") or ""
end

local function is_ip_token(ip)
    ip = trim(ip)
    if ip == "" or ip:lower() == "unknown" then return false end
    if ip:match("^%d+%.%d+%.%d+%.%d+$") then
        for octet in ip:gmatch("%d+") do
            local n = tonumber(octet)
            if not n or n < 0 or n > 255 then return false end
        end
        return true
    end
    if not ip:find(":", 1, true) then return false end
    if ip:find("[^%x:]") or ip:find(":::", 1, true) then return false end
    if (ip:sub(1, 1) == ":" and ip:sub(1, 2) ~= "::")
        or (ip:sub(-1) == ":" and ip:sub(-2) ~= "::") then
        return false
    end

    local _, compressions = ip:gsub("::", "")
    if compressions > 1 then return false end
    local has_compression = compressions == 1
    local groups = 0
    for part in ip:gmatch("[^:]+") do
        if #part < 1 or #part > 4 or not part:match("^%x+$") then return false end
        groups = groups + 1
    end
    return has_compression and groups < 8 or groups == 8
end

local function is_trusted_proxy(remote_ip)
    local trusted = config_list(get_config("trustedProxyIps", config.trustedProxyIps))
    for _, ip in ipairs(trusted) do
        if ip == "*" or ip == remote_ip then return true end
    end
    return false
end

local function get_header_value(headers, name)
    return headers[name] or headers[name:lower()]
end

local function client_ip_from_header(name, value)
    if type(value) == "table" then value = value[1] end
    if type(value) ~= "string" then return nil end
    if name:lower() == "x-forwarded-for" then
        local ips = {}
        for item in value:gmatch("[^,]+") do
            local ip = trim(item)
            if is_ip_token(ip) then ips[#ips + 1] = ip end
        end
        for i = #ips, 1, -1 do
            if not is_trusted_proxy(ips[i]) then return ips[i] end
        end
        return ips[1]
    end
    value = trim(value)
    if is_ip_token(value) then return value end
    return nil
end

local function getClientIp()
    local remote_ip = ngx.var.remote_addr or "unknown"
    if not is_trusted_proxy(remote_ip) then return remote_ip end

    local headers = get_headers()
    for _, name in ipairs(config_list(get_config("realIpHeaders", config.realIpHeaders))) do
        local ip = client_ip_from_header(name, get_header_value(headers, name))
        if ip then return ip end
    end
    return remote_ip
end

local function load_lfs()
    if lfs_checked then return lfs_mod end
    lfs_checked = true
    local ok, mod = pcall(require, "lfs")
    if ok then lfs_mod = mod end
    return lfs_mod
end

local function ensure_dir_component(fs, path)
    local mode = fs.attributes(path, "mode")
    if mode == "directory" then return true end
    if mode then
        ngx.log(ngx.ERR, "[WAF] log path exists but is not a directory: ", path)
        return false
    end
    local ok, err = fs.mkdir(path)
    if ok or fs.attributes(path, "mode") == "directory" then return true end
    ngx.log(ngx.ERR, "[WAF] failed to create logdir component: ", path, " err=", err)
    return false
end

local function ensure_log_dir(dir)
    if not dir or dir == "" then return false end
    if log_dir_attempted[dir] then return false end
    log_dir_attempted[dir] = true

    local fs = load_lfs()
    if not fs then
        ngx.log(ngx.ERR, "[WAF] lua-filesystem is unavailable; pre-create logdir: ", dir)
        return false
    end

    local path = tostring(dir):gsub("\\", "/"):gsub("/+$", "")
    if path == "" then return false end
    local current = ""
    if path:sub(1, 1) == "/" then current = "/" end
    local drive = path:match("^%a:")
    if drive then
        current = drive
        path = path:sub(#drive + 2)
    end
    for part in path:gmatch("[^/]+") do
        current = (current == "" or current == "/") and (current..part) or (current.."/"..part)
        if not ensure_dir_component(fs, current) then return false end
    end
    return true
end

local function write(file, msg)
    local fd = io.open(file, "ab")
    if not fd then
        local dir = file:match("^(.*)[/\\][^/\\]+$")
        if dir and ensure_log_dir(dir) then
            fd = io.open(file, "ab")
        end
    end
    if fd then
        fd:write(msg); fd:flush(); fd:close()
    else
        ngx.log(ngx.ERR, "[WAF] failed to write attack log: ", file)
    end
end

local function validate_shared_dicts()
    if shared_dicts_checked then return end
    shared_dicts_checked = true
    if not ngx.shared then
        ngx.log(ngx.ERR, "[WAF] ngx.shared is not available; shared dictionaries are required")
        return
    end
    if optionIsOn(get_config("CCDeny", config.CCDeny)) and not ngx.shared.limit then
        ngx.log(ngx.ERR, "[WAF] missing lua_shared_dict limit; CC protection is disabled")
    end
    if config.enable_cache ~= false and not ngx.shared.waf_cache then
        ngx.log(ngx.ERR, "[WAF] missing lua_shared_dict waf_cache; local cache is disabled")
    end
end

local function set_header_if_empty(name, value)
    if value and value ~= "" and ngx.header and ngx.header[name] == nil then
        ngx.header[name] = value
    end
end

local function apply_security_headers()
    if not optionIsOn(get_config("securityHeaders", config.securityHeaders or "off")) then return end
    set_header_if_empty("X-Content-Type-Options", "nosniff")
    set_header_if_empty("X-Frame-Options", "SAMEORIGIN")
    set_header_if_empty("Referrer-Policy", "strict-origin-when-cross-origin")
    set_header_if_empty("X-XSS-Protection", "1; mode=block")
    local csp = get_config("contentSecurityPolicy", config.contentSecurityPolicy)
    if csp and csp ~= "" then
        set_header_if_empty("Content-Security-Policy", csp)
    end
end

local function should_inspect_body(method)
    method = tostring(method or ""):upper()
    for _, item in ipairs(config_list(get_config("bodyInspectMethods", config.bodyInspectMethods or {"POST"}))) do
        if method == tostring(item):upper() then return true end
    end
    return false
end

local function shared_incr_with_ttl(dict, key, ttl)
    local count, err = dict:incr(key, 1)
    if count then return count end

    local ok, add_err = dict:add(key, 1, ttl)
    if ok then return 1 end

    count, err = dict:incr(key, 1)
    if count then return count end
    ngx.log(ngx.ERR, "[WAF] shared counter failed: key=", key, " err=", err or add_err or "-")
    return nil
end

local function alert_event(tag)
    if not optionIsOn(get_config("alertEnabled", config.alertEnabled or "off")) then return end
    local limit = ngx.shared and ngx.shared.limit
    if not limit then return end
    local window = tonumber(get_config("alertWindow", config.alertWindow or 60)) or 60
    local threshold = tonumber(get_config("alertThreshold", config.alertThreshold or 100)) or 100
    if window < 1 or threshold < 1 then return end
    local key = "waf:alert:"..ngx.today()..":"..(tag or "attack")
    local count = shared_incr_with_ttl(limit, key, window)
    if count and count == threshold then
        ngx.log(ngx.ERR, "[WAF] alert threshold reached: tag=", tag or "-", " count=", count, " window=", window)
    end
end

local function log(method, url, data, tag)
    if not optionIsOn(get_config("attacklog", config.attacklog)) then return end
    local ip, ua, sn, t, dir = getClientIp(), ngx.var.http_user_agent, ngx.var.server_name, ngx.localtime(), get_config("logdir", config.logdir)
    local line = ua and (ip.." ["..t.."] \""..method.." "..sn..url.."\" \""..(data or "-").."\"  \""..ua.."\" \""..tag.."\"\n")
                    or (ip.." ["..t.."] \""..method.." "..sn..url.."\" \""..(data or "-").."\" - \""..tag.."\"\n")
    write(dir..'/'..sn.."_"..ngx.today().."_sec.log", line)
    alert_event(tag)
end

local function say_html()
    if optionIsOn(get_config("Redirect", config.Redirect)) then
        ngx.header.content_type="text/html"; ngx.status=ngx.HTTP_FORBIDDEN; ngx.say(get_config("html", config.html)); ngx.exit(ngx.status)
    end
end

local function whiteurl()
    if not optionIsOn(get_config("whiteModule", config.whiteModule)) then return false end
    local rules = load_rules("whiteurl")
    if rules then for _, r in ipairs(rules) do if safe_match(ngx.var.uri, r, "whiteurl") then return true end end end
    return false
end

local function fileExtCheck(ext)
    if not ext then return false end
    ext = ext:lower()
    for _, v in ipairs(config.black_fileExt) do
        if ext == tostring(v):lower() then
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
            if data and type(data)~="boolean" and safe_match(safe_decode(data), r, "args") then
                log('GET', ngx.var.request_uri, data, r); say_html(); return true
            end
        end
    end
    return false
end

local function url()
    if not optionIsOn(get_config("UrlDeny", config.UrlDeny)) then return false end
    local rules = load_rules("url")
    if rules then for _, r in ipairs(rules) do if safe_match(safe_decode(ngx.var.request_uri), r, "url") then
        log('GET', ngx.var.request_uri, "-", r); say_html(); return true
    end end end
    return false
end

local function ua()
    local ua_str = ngx.var.http_user_agent
    if not ua_str then return false end
    local rules = load_rules("user-agent")
    if rules then for _, r in ipairs(rules) do if safe_match(ua_str, r, "user-agent") then
        log('UA', ngx.var.request_uri, "-", r); say_html(); return true
    end end end
    return false
end

local function cookie()
    if not optionIsOn(get_config("CookieMatch", config.CookieMatch)) then return false end
    local ck = ngx.var.http_cookie
    if not ck then return false end
    local rules = load_rules("cookie")
    if rules then for _, r in ipairs(rules) do if safe_match(safe_decode(ck), r, "cookie") then
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
            if data and type(data)~="boolean" and safe_match(safe_decode(data), r, "cmd") then
                log('GET', ngx.var.request_uri, data, r); say_html(); return true
            end
        end
    end
    return false
end

local function pathtraversal()
    if not optionIsOn(get_config("PathTraversalCheck", config.PathTraversalCheck)) then return false end
    local rules = load_rules("pathtraversal")
    if rules then for _, r in ipairs(rules) do if safe_match(safe_decode(ngx.var.request_uri), r, "pathtraversal") then
        log('GET', ngx.var.request_uri, "-", r); say_html(); return true
    end end end
    return false
end

local function sensitivefile()
    if not optionIsOn(get_config("SensitiveFileCheck", config.SensitiveFileCheck)) then return false end
    local rules = load_rules("sensitivefile")
    if rules then for _, r in ipairs(rules) do if safe_match(safe_decode(ngx.var.request_uri), r, "sensitivefile") then
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
            if data and type(data)~="boolean" and safe_match(safe_decode(data), r, "ssrf") then
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
            if data and type(data)~="boolean" and safe_match(safe_decode(data), r, "webshell") then
                log('GET', ngx.var.request_uri, data, r); say_html(); return true
            end
        end
    end
    return false
end

local post_rule_switches = {
    post = {"postMatch", config.postMatch},
    webshell = {"WebshellCheck", config.WebshellCheck},
    pathtraversal = {"PathTraversalCheck", config.PathTraversalCheck},
    cmd = {"CmdMatch", config.CmdMatch},
    ssrf = {"SSRFCheck", config.SSRFCheck},
    sensitivefile = {"SensitiveFileCheck", config.SensitiveFileCheck}
}

local function post_rule_enabled(rule_type)
    local switch = post_rule_switches[rule_type]
    if not switch then return true end
    return optionIsOn(get_config(switch[1], switch[2]))
end

local function post_body_rule(body_data, rule_type)
    if body_data == "" or not post_rule_enabled(rule_type) then return false end
    local rules = load_rules(rule_type)
    if rules then for _, r in ipairs(rules) do if safe_match(safe_decode(body_data), r, "post_"..rule_type) then
        log('POST', ngx.var.request_uri, body_data, r); say_html(); return true
    end end end
    return false
end

local function post_body_rules(body_data)
    local rule_params = get_config("RuleParams", config.RuleParams)
    local rule_types = (type(rule_params) == "table" and type(rule_params.post) == "table" and rule_params.post)
        or (config.RuleParams and config.RuleParams.post) or {"post"}
    for _, rule_type in ipairs(rule_types) do
        if post_body_rule(body_data, rule_type) then return true end
    end
    return false
end

local function parse_cc_rate(rate)
    if type(rate) ~= "string" then rate = tostring(rate or "") end
    local cnt, sec = rate:match("^%s*(%d+)%s*/%s*(%d+)%s*$")
    cnt, sec = tonumber(cnt), tonumber(sec)
    if cnt and sec and cnt > 0 and sec > 0 then
        return cnt, sec
    end
    return nil, nil
end

local function cc_block()
    ngx.header.content_type="text/html"
    ngx.status=ngx.HTTP_FORBIDDEN
    ngx.say(get_config("html", config.html))
    ngx.exit(ngx.status)
    return true
end

local function cc_limit_token(ip, uri)
    local scope = get_config("CCScope", config.CCScope or "ip")
    if scope == "ip_uri" then return "cc:"..ip..":"..(uri or "") end
    return "cc:"..ip
end

local function cleanup_cc_ban_cache(now, current_ip)
    if current_ip and cc_ban_cache.ip_map[current_ip] and cc_ban_cache.ip_map[current_ip] <= now then
        cc_ban_cache.ip_map[current_ip] = nil
        cc_ban_cache.last_sync_by_ip[current_ip] = nil
    end

    local interval = tonumber(get_config("CCCleanupInterval", config.CCCleanupInterval or 1)) or 1
    if interval < 1 then interval = 1 end
    if now - cc_ban_cache.last_cleanup_time < interval then return end

    cc_ban_cache.last_cleanup_time = now
    for ip, expires_at in pairs(cc_ban_cache.ip_map) do
        if expires_at <= now then
            cc_ban_cache.ip_map[ip] = nil
            cc_ban_cache.last_sync_by_ip[ip] = nil
        end
    end
end

local function cc_ban_key(ip)
    return "cc:ban:"..ip
end

local function shared_cc_ban_expires_at(ip, ban_time, now, limit)
    if not limit then return nil end
    local expires_at = limit:get(cc_ban_key(ip))
    if not expires_at then return nil end
    expires_at = tonumber(expires_at)
    if not expires_at or expires_at <= now then
        expires_at = now + ban_time
    end
    return expires_at
end

local function set_cc_ban(ip, ban_time, now, limit, sync_redis)
    local expires_at = now + ban_time
    if limit then
        local ok, err = limit:set(cc_ban_key(ip), expires_at, ban_time)
        if not ok then ngx.log(ngx.ERR, "[WAF] failed to set shared CC ban: ", err or "-") end
    end
    cc_ban_cache.ip_map[ip] = expires_at
    if sync_redis and waf_redis then waf_redis.cc_ban_set(ip, ban_time) end
end

local function is_cc_banned(ip, ban_time, now, limit)
    cleanup_cc_ban_cache(now, ip)
    local shared_expires_at = shared_cc_ban_expires_at(ip, ban_time, now, limit)
    if shared_expires_at then
        cc_ban_cache.ip_map[ip] = shared_expires_at
        return true
    end

    local local_expires_at = cc_ban_cache.ip_map[ip]
    if local_expires_at and local_expires_at > now then
        if limit then
            local ok, err = limit:set(cc_ban_key(ip), local_expires_at, local_expires_at - now)
            if not ok then ngx.log(ngx.ERR, "[WAF] failed to refresh shared CC ban: ", err or "-") end
        end
        return true
    end

    local last_sync = cc_ban_cache.last_sync_by_ip[ip] or 0
    if now - last_sync <= cc_ban_cache.sync_interval then
        return false
    end
    for k, v in pairs(cc_ban_cache.ip_map) do
        if v <= now then cc_ban_cache.ip_map[k] = nil end
    end
    local redis_banned = waf_redis and waf_redis.cc_ban_check(ip)
    if redis_banned == true then
        cc_ban_cache.last_sync_time = now
        cc_ban_cache.last_sync_by_ip[ip] = now
        set_cc_ban(ip, ban_time, now, limit, false)
        return true
    end
    if redis_banned == false then
        cc_ban_cache.last_sync_time = now
        cc_ban_cache.last_sync_by_ip[ip] = now
    end
    return false
end

local function denycc()
    ensure_modules_loaded()
    if not optionIsOn(get_config("CCDeny", config.CCDeny)) then return false end
    local uri, rate, ip = ngx.var.uri, get_config("CCrate", config.CCrate), getClientIp()
    local ban_time = tonumber(get_config("CCBanTime", config.CCBanTime or 3600)) or 3600
    if ban_time <= 0 then ban_time = 3600 end
    local cnt, sec = parse_cc_rate(rate)
    if not cnt then
        cnt, sec = parse_cc_rate(config.CCrate)
    end
    if not cnt then
        ngx.log(ngx.ERR, "[WAF] invalid CCrate: ", rate)
        return false
    end
    
    -- 先检查本地封禁缓存
    local now = ngx.time()
    local limit, token = ngx.shared and ngx.shared.limit, cc_limit_token(ip, uri)
    if is_cc_banned(ip, ban_time, now, limit) then
        return cc_block()
    end

    -- 使用共享内存原子递增，避免 get 后 incr 的竞态
    if not limit then
        ngx.log(ngx.ERR, "[WAF] lua_shared_dict limit is not configured")
        return false
    end
    local req = shared_incr_with_ttl(limit, token, sec)
    if not req then return false end
    if req > cnt then
        set_cc_ban(ip, ban_time, now, limit, true)
        return cc_block()
    end
    return false
end

local function get_boundary()
    local headers = get_headers()
    local h = headers["content-type"] or headers["Content-Type"]
    if not h then return nil end
    if type(h)=="table" then h=h[1] end
    if type(h) ~= "string" then return nil end
    for param in h:gmatch("[^;]+") do
        local name, value = param:match("^%s*([^=]+)%s*=%s*(.-)%s*$")
        if name and name:lower() == "boundary" and value and value ~= "" then
            return value:gsub('^"(.*)"$', "%1"):gsub("^'(.*)'$", "%1")
        end
    end
    return nil
end

local function reject_large_body(size)
    log('BODY', ngx.var.request_uri, tostring(size or "-"), "request body too large")
    ngx.header.content_type="text/html"
    ngx.status=ngx.HTTP_REQUEST_ENTITY_TOO_LARGE or 413
    ngx.say(get_config("html", config.html))
    ngx.exit(ngx.status)
    return true
end

local function request_body_too_large()
    local max_size = tonumber(get_config("maxRequestBodySize", config.maxRequestBodySize or 0)) or 0
    if max_size <= 0 then return false end
    local content_length = tonumber(ngx.var.http_content_length or 0) or 0
    return content_length > max_size, content_length
end

local function body_data_too_large(body_data)
    local max_size = tonumber(get_config("maxRequestBodySize", config.maxRequestBodySize or 0)) or 0
    return max_size > 0 and body_data and #body_data > max_size
end

local function read_body_file_limited(path, max_size)
    local fd = io.open(path, "rb")
    if not fd then return nil end

    local size = fd:seek("end")
    fd:seek("set", 0)
    if max_size > 0 and size and size > max_size then
        fd:close()
        return nil, "too_large", size
    end

    local chunks, total = {}, 0
    while true do
        local chunk = fd:read(8192)
        if not chunk then break end
        total = total + #chunk
        if max_size > 0 and total > max_size then
            fd:close()
            return nil, "too_large", total
        end
        chunks[#chunks + 1] = chunk
    end
    fd:close()

    return table.concat(chunks)
end

local function read_request_body()
    local too_large, size = request_body_too_large()
    if too_large then return nil, "too_large", size end

    ngx.req.read_body()
    local max_size = tonumber(get_config("maxRequestBodySize", config.maxRequestBodySize or 0)) or 0
    local body_data = ngx.req.get_body_data()
    if body_data then
        if max_size > 0 and #body_data > max_size then
            return nil, "too_large", #body_data
        end
        return body_data
    end
    local f = ngx.req.get_body_file()
    if not f then return nil end
    return read_body_file_limited(f, max_size)
end

local function check_upload_ext(body_data, boundary)
    if not body_data or body_data == "" then return false end
    if not boundary then return false end
    local seen = {}
    local patterns = {
        'filename%s*=%s*"([^"]*)"',
        "filename%s*=%s*'([^']*)'",
        "filename%*%s*=%s*[^']*''([^;%s]+)"
    }
    for _, pattern in ipairs(patterns) do
        for filename in body_data:gmatch(pattern) do
            filename = safe_decode(filename)
            if filename ~= "" and not seen[filename] then
                seen[filename] = true
                local ext = filename:match("%.([^%.\\/%\"]+)$")
                if ext and fileExtCheck(ext) then return true end
            end
        end
    end
    return false
end

local function inspect_post_body(boundary)
    local too_large, size = request_body_too_large()
    if too_large then return reject_large_body(size) end
    local body_data, err, body_size = read_request_body()
    if err == "too_large" then return reject_large_body(body_size) end
    if not body_data then return false end
    if body_data_too_large(body_data) then return reject_large_body(#body_data) end
    if post_body_rules(body_data) then return true end
    return check_upload_ext(body_data, boundary)
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
end

-- WAF 主函数（导出供调用）
local function reload_waf(token)
    local expected = get_config("reloadToken", config.reloadToken)
    if expected and expected ~= "" and token ~= expected then
        ngx.log(ngx.ERR, "[WAF] reload rejected: invalid token")
        return false, "invalid token"
    end

    worker_cache.last_load_time = 0
    worker_cache.ip_cache_version = nil
    worker_cache.last_ip_version_check_time = 0
    for rule_type in pairs(rules_cache) do rules_cache[rule_type] = {} end
    for ip in pairs(ip_whitelist_map) do ip_whitelist_map[ip] = nil end
    for ip in pairs(ip_blocklist_map) do ip_blocklist_map[ip] = nil end
    if waf_cache and waf_cache.flush_all then waf_cache.flush_all() end

    load_config()
    for _, t in ipairs{"url","args","post","cookie","user-agent","whiteurl","cmd","ssrf","pathtraversal","sensitivefile","webshell"} do load_rules(t) end
    load_ip_lists_if_changed()
    ngx.log(ngx.NOTICE, "[WAF] reload completed")
    return true
end

local function run_waf()
    local ok, err = pcall(function()
        load_ip_lists_if_changed()
        load_all()
        validate_shared_dicts()
        apply_security_headers()

        if whiteip() then return end
        if blockip() then return end

        if whiteurl() then return end
        if denycc() then return end
        if url() then return end
        if sensitivefile() then return end
        if pathtraversal() then return end

        if is_static_request() and get_config("static_skip", config.static_skip) == "light" then
            return
        end

        if args() then return end
        if cmd() then return end
        if ssrf() then return end
        if webshell() then return end
        if ua() then return end
        if cookie() then return end

        local method, boundary = ngx.req.get_method(), get_boundary()
        if should_inspect_body(method) then
            if inspect_post_body(boundary) then return end
        end
    end)

    if not ok then
        ngx.log(ngx.ERR, "[WAF] Error: ", err)
    end
end

-- 导出模块
local _M = {}
_M.run = run_waf
_M.reload = reload_waf
return _M
