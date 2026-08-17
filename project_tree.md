# ngx_lua_waf 项目结构

基于 OpenResty (Nginx + Lua) 的高性能 Web 应用防火墙。

`
ngx_lua_waf/
├── .codegraph/                    # 代码索引数据库
│   └── codegraph.db
│
├── admin/                         # 管理工具（Python）
│   ├── __pycache__/
│   │   └── init_redis.cpython-313.pyc
│   └── init_redis.py              # Redis 初始化脚本
│
├── tests/                         # 测试用例（Python）
│   ├── __pycache__/
│   │   ├── __init__.cpython-313.pyc
│   │   ├── test_cache_independence.cpython-313.pyc
│   │   ├── test_p0_waf_fixes.cpython-313.pyc
│   │   ├── test_p1_stability_fixes.cpython-313.pyc
│   │   ├── test_p2_compatibility_fixes.cpython-313.pyc
│   │   ├── test_post_rule_params.cpython-313.pyc
│   │   ├── test_prometheus_metrics.cpython-313.pyc
│   │   ├── test_security_enhancements.cpython-313.pyc
│   │   └── test_url_rules.cpython-313.pyc
│   ├── __init__.py
│   ├── test_cache_independence.py
│   ├── test_p0_waf_fixes.py
│   ├── test_p1_stability_fixes.py
│   ├── test_p2_compatibility_fixes.py
│   ├── test_post_rule_params.py
│   ├── test_prometheus_metrics.py
│   ├── test_security_enhancements.py
│   └── test_url_rules.py
│
├── wafconf/                       # WAF 规则配置文件
│   ├── args                       # 参数注入检测规则
│   ├── cmd                        # 命令注入检测规则
│   ├── cookie                     # Cookie 检测规则
│   ├── pathtraversal              # 路径穿越检测规则
│   ├── post                       # POST 数据检测规则
│   ├── sensitivefile              # 敏感文件检测规则
│   ├── ssrf                       # SSRF 检测规则
│   ├── url                        # URL 攻击检测规则
│   ├── user-agent                 # User-Agent 检测规则
│   ├── webshell                   # WebShell 检测规则
│   └── whiteurl                   # URL 白名单规则
│
├── cache.lua                      # 缓存模块
├── config.lua                     # 配置模块
├── init.lua                       # 初始化入口
├── metrics.lua                    # Prometheus 指标模块
├── README.md                      # 项目说明文档
├── redis.lua                      # Redis 操作模块
└── waf.lua                        # WAF 核心逻辑
`

## 模块说明

| 文件/目录 | 说明 |
|-----------|------|
| init.lua | WAF 初始化入口，OpenResty 启动时加载 |
| waf.lua | WAF 核心逻辑，规则匹配与拦截处理 |
| config.lua | 配置管理，读取配置项与默认值 |
| cache.lua | 缓存模块，规则/白名单等缓存 |
| edis.lua | Redis 操作封装，规则与配置的持久化 |
| metrics.lua | Prometheus 监控指标暴露 |
| wafconf/ | 内置攻击检测规则集（正则表达式） |
| dmin/ | Redis 数据初始化管理工具 |
| 	ests/ | Python 测试用例集 |