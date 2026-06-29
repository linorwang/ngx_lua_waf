# ngx_lua_waf - 简单好用的 Web 防火墙

基于 OpenResty (Nginx + Lua) 的高性能 Web 应用防火墙，帮你挡住 SQL 注入、XSS 攻击等常见威胁。

---

## 🚀 5 分钟快速上手

### 第一步：准备环境

确保你已经安装了：
- **OpenResty**（就是带 Lua 的 Nginx）
- **Redis**（用来存配置和规则）
- **Python 3**（用来初始化数据）

检查一下：
```bash
# 检查 OpenResty
/usr/local/openresty/bin/openresty -v

# 检查 Redis
redis-cli ping
# 应该返回 PONG

# 检查 Python
python3 --version
mkdir -p /opt/waf
python3 -m venv /opt/waf/
source /opt/waf/bin/activate
pip install --upgrade pip
pip install redis
```

### 第二步：安装 WAF

```bash
# 进入 OpenResty 配置目录
cd /usr/local/openresty/nginx/conf

# 下载项目（或者直接复制文件）
git clone https://github.com/linorwang/ngx_lua_waf.git waf

# 或者如果你已经下载了，直接复制
# cp -r /path/to/ngx_lua_waf /usr/local/openresty/nginx/conf/waf
```

### 第三步：配置 Nginx

编辑 `/usr/local/openresty/nginx/conf/nginx.conf`，在 `http { ... }` 里面添加：

```nginx
http {
    # ... 原有配置保持不变 ...

    # ---------------- WAF 配置开始 ----------------
    lua_shared_dict limit 256m;
    lua_shared_dict waf_cache 50m;
    lua_package_path "/usr/local/openresty/nginx/conf/waf/?.lua;;";

    init_by_lua_block {
        require "init"
    }
    # ---------------- WAF 配置结束 ----------------

    server {
        listen 80;
        server_name your-domain.com;  # 改成你的域名或 IP

        # ---------------- WAF 检查（必须加）----------------
        access_by_lua_block {
            local waf = require "waf"
            waf.run()
        }
        # ---------------- WAF 检查结束 ----------------

        location / {
            root html;
            index index.html index.htm;
        }
    }
}
```

> `limit` 用于 CC 防护计数，`waf_cache` 用于本地配置与规则缓存，二者都需要配置在 `http` 块内。`logdir` 指向的目录需要允许 OpenResty worker 写入；建议部署时预先创建目录。若运行环境安装了 `lua-filesystem`，WAF 可在不调用 shell 的情况下创建目录，失败时会写入 Nginx error log。

### 安全增强配置

编辑 `config.lua` 可配置以下选项：
```lua
-- 最大请求体大小，单位字节；0 表示不限制
maxRequestBodySize = 10485760
-- 建议同时在 Nginx 配置 client_max_body_size 10m，在读取请求体前拦截超大请求

-- 攻击日志告警：alertWindow 秒内达到 alertThreshold 次会写入 Nginx error log
alertEnabled = "on"
alertThreshold = 100
alertWindow = 60

-- 静态资源跳过检测："light" 表示静态资源只进行基础检测，"off" 表示全部检测
static_skip = "light"

-- 真实 IP 获取头和受信任代理 IP
realIpHeaders = {"X-Forwarded-For", "X-Real-IP"}
trustedProxyIps = {"127.0.0.1", "::1"}

-- 需要检测请求体的 HTTP 方法
bodyInspectMethods = {"POST", "PUT", "PATCH", "DELETE"}

-- 安全响应头；contentSecurityPolicy 为空时不会设置 CSP，避免误伤现有静态资源
securityHeaders = "on"
contentSecurityPolicy = ""

-- 可选：给热加载接口设置 token
reloadToken = "change-me"
```

如需暴露热加载接口，建议只允许内网访问，并校验 `reloadToken`：

```nginx
location = /waf/reload {
    allow 127.0.0.1;
    deny all;
    content_by_lua_block {
        local waf = require "waf"
        local ok, err = waf.reload(ngx.var.arg_token)
        ngx.status = ok and 200 or 403
        ngx.say(ok and "ok" or err)
    }
}
```

### 第四步：配置 Redis

编辑 `/usr/local/openresty/nginx/conf/waf/config.lua`：

```lua
local function env(name)
    local value = os.getenv(name)
    if value == "" then return nil end
    return value
end

-- 启用 Redis 模式
use_redis = true

-- Redis 连接配置
redis_host = "127.0.0.1"
redis_port = 6379
redis_db = 0
-- Redis 6.0+ ACL 用户名，没有则设为 nil
redis_username = env("WAF_REDIS_USERNAME")
-- Redis 密码，没有则设为 nil
redis_password = env("WAF_REDIS_PASSWORD")
redis_timeout = 1000  -- 毫秒
redis_pool_size = 1000
redis_idle_timeout = 10000  -- 毫秒

-- 本地缓存配置
cache_ttl = 60  -- 秒，配置和规则缓存过期时间
ip_cache_check_interval = 1  -- 秒，IP 黑白名单版本检查间隔
```

OpenResty worker 读取环境变量时，需要在 Nginx 主配置中显式透传，例如：

```nginx
env WAF_REDIS_USERNAME;
env WAF_REDIS_PASSWORD;
```

### 第五步：初始化数据

```bash
# 进入管理目录
cd /usr/local/openresty/nginx/conf/waf/admin

# 安装 Python redis 模块
pip3 install redis

# 初始化 Redis 数据
python3 init_redis.py

# 也可以使用命令行参数
# python3 init_redis.py --rule-path /path/to/rules  # 指定规则目录
# python3 init_redis.py --dry-run  # 只读取配置不写入 Redis
```

看到 `Redis initialization complete.` 就成功了！

### 第六步：启动！

```bash
# 先测试配置对不对
/usr/local/openresty/nginx/sbin/nginx -t

# 启动 OpenResty
/usr/local/openresty/nginx/sbin/nginx

# 如果已经在运行，就重新加载
/usr/local/openresty/nginx/sbin/nginx -s reload
```

---

## ✅ 测试一下 WAF 有没有生效

试试这些命令，看会不会被拦截：

```bash
# 正常请求（应该返回 200）
curl -v "http://localhost/"

# SQL 注入测试（应该返回 403 被拦截）
curl -v "http://localhost/?id=1' OR '1'='1"

# XSS 攻击测试（应该返回 403 被拦截）
curl -v "http://localhost/?q=<script>alert(1)</script>"
```

### 新增防护功能测试命令

```bash
# 命令注入测试（应该返回 403 被拦截）
curl -v "http://localhost/?cmd=1;ls"
curl -v "http://localhost/?cmd=1&&whoami"
curl -v "http://localhost/?cmd=\`echo hacked\`"
curl -v "http://localhost/?cmd=\$(id)"

# SSRF 攻击测试（应该返回 403 被拦截）
curl -v "http://localhost/?url=http://127.0.0.1"
curl -v "http://localhost/?url=http://192.168.1.1"
curl -v "http://localhost/?url=http://10.0.0.1"
curl -v "http://localhost/?url=http://localhost"

# 路径遍历测试（应该返回 403 被拦截）
curl -v "http://localhost/../etc/passwd"
curl -v "http://localhost/?file=../../etc/passwd"
curl -v "http://localhost/?file=..%2f..%2fetc%2fpasswd"
curl -v "http://localhost/?path=/windows/system32"

# 敏感文件访问测试（应该返回 403 被拦截）
curl -v "http://localhost/.git/config"
curl -v "http://localhost/.env"
curl -v "http://localhost/phpinfo.php"
curl -v "http://localhost/backup.sql"
curl -v "http://localhost/backup.zip"

# Webshell 特征测试（应该返回 403 被拦截）
curl -v "http://localhost/?code=eval(\$_POST[1])"
curl -v "http://localhost/?code=assert(\$_POST[1])"
curl -v "http://localhost/?cmd=system('whoami')"
```

如果攻击请求返回 `403 Forbidden`，说明 WAF 已经在工作了！🎉

---

## 🛠️ 常用管理命令（使用 redis-cli）

直接用 `redis-cli` 来管理 WAF，简单方便！

### 查看配置
```bash
# 查看所有配置
redis-cli HGETALL waf:config

# 查看单个配置
redis-cli HGET waf:config attacklog
```

### 修改配置
```bash
# 开启攻击日志
redis-cli HSET waf:config attacklog on

# 开启 CC 防护
redis-cli HSET waf:config CCDeny on

# 设置 CC 频率（100次/60秒）
redis-cli HSET waf:config CCrate "100/60"

# 设置 CC 封禁时间（秒）
redis-cli HSET waf:config CCBanTime 3600

# 设置 CC 防护范围："ip" 或 "ip_uri"
redis-cli HSET waf:config CCScope ip

# 新增防护功能开关配置
redis-cli HSET waf:config CmdMatch on          # 开启命令注入防护
redis-cli HSET waf:config SSRFCheck on         # 开启 SSRF 防护
redis-cli HSET waf:config PathTraversalCheck on  # 开启路径遍历防护
redis-cli HSET waf:config SensitiveFileCheck on  # 开启敏感文件防护
redis-cli HSET waf:config WebshellCheck on     # 开启 Webshell 检测

# 其他配置
redis-cli HSET waf:config static_skip light    # 静态资源检测模式：light/off
redis-cli HSET waf:config maxRequestBodySize 10485760  # 最大请求体大小（字节）
redis-cli HSET waf:config alertEnabled on      # 开启告警
redis-cli HSET waf:config alertThreshold 100   # 告警阈值
redis-cli HSET waf:config alertWindow 60       # 告警时间窗口（秒）
redis-cli HSET waf:config securityHeaders on   # 开启安全响应头
redis-cli HSET waf:config contentSecurityPolicy ""  # 可选 CSP，留空表示不设置

# ⚠️ 重要：修改配置后必须增加版本号，让 WAF 重新加载
redis-cli INCR waf:version:config
```

### 规则管理
```bash
# 查看各类规则
redis-cli SMEMBERS waf:rules:url
redis-cli SMEMBERS waf:rules:args
redis-cli SMEMBERS waf:rules:post
redis-cli SMEMBERS waf:rules:cookie
redis-cli SMEMBERS waf:rules:user-agent
redis-cli SMEMBERS waf:rules:whiteurl
redis-cli SMEMBERS waf:rules:cmd
redis-cli SMEMBERS waf:rules:ssrf
redis-cli SMEMBERS waf:rules:pathtraversal
redis-cli SMEMBERS waf:rules:sensitivefile
redis-cli SMEMBERS waf:rules:webshell

# 添加新规则示例
redis-cli SADD waf:rules:sensitivefile "\.secret"

# 删除规则
redis-cli SREM waf:rules:sensitivefile "\.secret"

# ⚠️ 重要：修改后增加版本号
redis-cli INCR waf:version:rules
```

### IP 黑名单管理
```bash
# 查看黑名单
redis-cli SMEMBERS waf:ip:blocklist

# 添加 IP 到黑名单
redis-cli SADD waf:ip:blocklist 1.2.3.4

# 从黑名单删除 IP
redis-cli SREM waf:ip:blocklist 1.2.3.4

# ⚠️ 重要：修改后增加版本号（IP 列表会在 1 秒内生效）
redis-cli INCR waf:version:ip
```

### IP 白名单管理
```bash
# 查看白名单
redis-cli SMEMBERS waf:ip:whitelist

# 添加 IP 到白名单
redis-cli SADD waf:ip:whitelist 192.168.1.100

# 从白名单删除 IP
redis-cli SREM waf:ip:whitelist 192.168.1.100

# ⚠️ 重要：修改后增加版本号
redis-cli INCR waf:version:ip
```

### 刷新缓存（让配置立即生效）
```bash
# 刷新配置
redis-cli INCR waf:version:config

# 刷新规则
redis-cli INCR waf:version:rules

# 刷新 IP 列表
redis-cli INCR waf:version:ip

# 或者一次性刷新所有
redis-cli INCR waf:version:config
redis-cli INCR waf:version:rules
redis-cli INCR waf:version:ip
```

---

## 📁 项目结构

```
ngx_lua_waf/
├── config.lua          # 配置文件
├── waf.lua             # WAF 核心代码
├── redis.lua           # Redis 操作
├── cache.lua           # 缓存模块
├── init.lua            # 初始化脚本
├── admin/              # 管理工具
│   └── init_redis.py   # 初始化数据（用这个）
├── wafconf/            # 规则文件
│   ├── url             # URL 拦截规则
│   ├── args            # GET 参数规则
│   ├── post            # POST 参数规则
│   ├── cookie          # Cookie 规则
│   ├── user-agent      # User-Agent 规则
│   ├── whiteurl        # 白名单 URL
│   ├── cmd             # 命令注入规则
│   ├── ssrf            # SSRF 规则
│   ├── pathtraversal   # 路径遍历规则
│   ├── sensitivefile   # 敏感文件规则
│   └── webshell        # Webshell 规则
└── tests/              # 测试文件
```

---

## 🎯 功能特性

### 核心防护功能
- ✅ SQL 注入防护
- ✅ XSS 跨站脚本防护
- ✅ 文件上传攻击防护
- ✅ 恶意爬虫拦截
- ✅ IP 黑名单/白名单
- ✅ CC 攻击防护

### 新增防护功能
- ✅ 命令注入防护（CmdMatch）- 检测 `&&`、`||`、`;`、`$()`、反引号等
- ✅ SSRF 攻击防护（SSRFCheck）- 检测内网地址请求
- ✅ 路径遍历防护（PathTraversalCheck）- 检测 `../`、`..\` 等
- ✅ 敏感文件访问防护（SensitiveFileCheck）- 检测 `.git`、`.env` 等
- ✅ Webshell 检测防护（WebshellCheck）- 检测危险函数调用

### 高级特性
- ✅ Redis 集中管理，热更新规则和配置
- ✅ 本地缓存机制，减少 Redis 查询
- ✅ IP 黑白名单实时生效（默认 1 秒内）
- ✅ 详细的攻击日志
- ✅ 美观的拦截页面
- ✅ 真实 IP 获取（支持 X-Forwarded-For 等头）
- ✅ 受信任代理 IP 配置
- ✅ 静态资源跳过检测
- ✅ 请求体大小限制
- ✅ 攻击告警机制
- ✅ 热重载接口
- ✅ POST 请求多规则支持
- ✅ 正则安全检查（拒绝危险正则）
- ✅ URL 多层解码
- ✅ CC 防护支持 IP 或 IP+URI 范围

---

## ⚙️ 配置说明

### config.lua 主要配置项

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `use_redis` | 是否启用 Redis | `true` |
| `redis_host` | Redis 主机 | `127.0.0.1` |
| `redis_port` | Redis 端口 | `6379` |
| `redis_db` | Redis DB | `0` |
| `redis_username` | Redis ACL 用户名 | `env("WAF_REDIS_USERNAME")` |
| `redis_password` | Redis 密码 | `env("WAF_REDIS_PASSWORD")` |
| `cache_ttl` | 配置/规则缓存时间（秒） | `60` |
| `ip_cache_check_interval` | IP 列表版本检查间隔（秒） | `1` |
| `decode_depth` | URL 解码深度 | `2` |
| `static_skip` | 静态资源检测模式：`light`/`off` | `light` |
| `maxRegexLength` | 最大正则长度 | `512` |
| `rejectUnsafeRegex` | 是否拒绝危险正则 | `on` |
| `attacklog` | 是否开启攻击日志 | `off` |
| `logdir` | 日志目录 | `/usr/local/openresty/nginx/logs/hack/` |
| `UrlDeny` | URL 拦截开关 | `on` |
| `CookieMatch` | Cookie 检测开关 | `on` |
| `postMatch` | POST 参数检测开关 | `on` |
| `whiteModule` | 白名单模块开关 | `on` |
| `CmdMatch` | 命令注入防护开关 | `on` |
| `SSRFCheck` | SSRF 防护开关 | `on` |
| `PathTraversalCheck` | 路径遍历防护开关 | `on` |
| `SensitiveFileCheck` | 敏感文件防护开关 | `on` |
| `WebshellCheck` | Webshell 检测开关 | `on` |
| `ResponseFilter` | 响应过滤开关 | `off` |
| `securityHeaders` | 是否设置基础安全响应头 | `on` |
| `contentSecurityPolicy` | 可选 CSP 响应头，留空表示不设置 | `""` |
| `realIpHeaders` | 真实 IP 获取头（逗号分隔） | `X-Forwarded-For,X-Real-IP` |
| `trustedProxyIps` | 受信任代理 IP（逗号分隔） | `127.0.0.1,::1` |
| `bodyInspectMethods` | 需要检测请求体的方法（逗号分隔） | `POST,PUT,PATCH,DELETE` |
| `CCBanTime` | CC 封禁时间（秒） | `3600` |
| `CCScope` | CC 防护范围：`ip`/`ip_uri` | `ip` |
| `CCCleanupInterval` | CC 封禁缓存清理间隔（秒） | `1` |
| `maxRequestBodySize` | 最大请求体大小（字节） | `10485760` |
| `alertEnabled` | 是否开启攻击告警 | `on` |
| `alertThreshold` | 告警阈值（次数） | `100` |
| `alertWindow` | 告警时间窗口（秒） | `60` |
| `reloadToken` | 热重载 token | `""` |

---

## ❓ 遇到问题？

### 问题 1：启动 OpenResty 报错
先检查配置语法：
```bash
/usr/local/openresty/nginx/sbin/nginx -t
```

### 问题 2：Redis 连接失败
确认 Redis 正在运行：
```bash
redis-cli ping
```
检查 config.lua 中的 Redis 连接配置是否正确。

### 问题 3：规则不生效
刷新一下缓存：
```bash
redis-cli INCR waf:version:config
redis-cli INCR waf:version:rules
redis-cli INCR waf:version:ip
```

### 问题 4：IP 黑白名单不生效
IP 列表默认会在 1 秒内自动生效，确保增加了版本号：
```bash
redis-cli INCR waf:version:ip
```

### 问题 5：静态资源也被检测
检查 `static_skip` 配置：
```bash
redis-cli HGET waf:config static_skip
# 设置为 "light" 可以让静态资源跳过部分检测
redis-cli HSET waf:config static_skip light
redis-cli INCR waf:version:config
```

---

## 📄 License

MIT License

---

## IP 黑名单即时生效说明

添加或删除 IP 后仍需要执行：

```bash
redis-cli INCR waf:version:ip
```

WAF 会按 `ip_cache_check_interval` 配置在每个 worker 内短间隔检查 `waf:version:ip`，默认最多 1 秒发现版本变化并重新加载黑白名单，不再受 `cache_ttl` 的 60 秒本地刷新间隔限制。黑名单 IP 会先于静态资源跳过逻辑被拦截，因此会对全站请求生效。

---

## 🧪 测试

项目包含完整的测试套件，在 `tests/` 目录下。可以使用测试来验证 WAF 功能是否正常工作。

---

**就这么简单！快去试试吧！** 🚀
