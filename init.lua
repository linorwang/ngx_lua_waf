local config = require "config"

-- 注意：无论是 Redis 模式还是文件模式，init.lua 在 init_by_lua 阶段都不执行实际逻辑
-- 因为原始的 init.lua.original 包含了 io.open, ngx.var 等只能在请求阶段使用的代码
-- 所有实际的 WAF 逻辑都在 waf.lua 的 access_by_lua 阶段执行
