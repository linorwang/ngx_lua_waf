local config = require "config"

if not config.use_redis then
    dofile(ngx.config.prefix() .. "conf/waf/init.lua.original")
    return
end

-- Redis 模式下，init_by_lua 阶段不做任何 Redis 操作
-- 所有 Redis 操作在 waf.lua 的请求阶段进行
-- 只需要把模块和配置暴露给 waf.lua
