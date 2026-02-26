local config = require "config"
if not config.use_redis then dofile(ngx.config.prefix().."conf/waf/waf.lua.original"); return end

local cl, method, ngxmatch = tonumber(ngx.req.get_headers()['content-length']), ngx.req.get_method(), ngx.re.match

if whiteip() or blockip() or denycc() then return end
if ngx.var.http_Acunetix_Aspect or ngx.var.http_X_Scan_Memo then ngx.exit(444); return end
if whiteurl() or ua() or url() or args() or cookie() then return end
if method ~= "POST" then return end

local boundary = get_boundary()
if boundary then
    local len, sock, err = string.len, ngx.req.socket()
    if not sock then return end
    ngx.req.init_body(128*1024); sock:settimeout(0)
    local chunk_size = 4096; if cl and cl < chunk_size then chunk_size = cl end
    local size, filetranslate = 0, false
    while size < cl do
        local data, err, partial = sock:receive(chunk_size); data = data or partial
        if not data then return end
        ngx.req.append_body(data); if body(data) then return end
        size = size + len(data)
        local m = ngxmatch(data, [[Content-Disposition: form-data;(.+)filename="(.+)\\.(.*)"]], 'ijo')
        if m then fileExtCheck(m[3]); filetranslate = true
        else
            if ngxmatch(data, "Content-Disposition:", 'isjo') then filetranslate = false end
            if not filetranslate then if body(data) then return end end
        end
        local less = cl - size; if less < chunk_size then chunk_size = less end
    end
    ngx.req.finish_body()
else
    ngx.req.read_body(); local args = ngx.req.get_post_args(); if not args then return end
    for key, val in pairs(args) do
        local data
        if type(val) == "table" then if type(val[1]) == "boolean" then return end; data = table.concat(val, ", ")
        else data = val end
        if data and type(data) ~= "boolean" and body(data) then body(key) end
    end
end
