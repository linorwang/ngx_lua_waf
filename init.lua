-- 初始化脚本 - 在 OpenResty 启动时执行
-- 这个阶段不能执行任何可能导致 yield 的操作（如网络请求、Redis 连接等）

local config = require "config"

-- 安全检查：确保配置模块已加载
if not config then
    ngx.log(ngx.ERR, "[WAF Init] Failed to load config module")
else
    ngx.log(ngx.NOTICE, "[WAF Init] Config module loaded successfully")
    ngx.log(ngx.NOTICE, "[WAF Init] Redis enabled: ", config.use_redis)
end

-- 注意：
-- 1. init_by_lua_block 阶段不能连接 Redis（会导致 yield）
-- 2. 实际的 Redis 连接和配置加载在 access_by_lua_block 阶段（waf.lua）进行
-- 3. 这里只做基础模块的预加载和配置验证
