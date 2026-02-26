# OpenResty + Redis WAF 防火墙

基于 OpenResty (Nginx + Lua) 和 Redis 实现的高性能 Web 应用防火墙 (WAF)。

---

## 目录

- [功能特性](#功能特性)
- [快速开始](#快速开始)
- [手把手配置 Nginx](#手把手配置-nginx)
- [测试与验证](#测试与验证)
- [架构设计](#架构设计)
- [配置说明](#配置说明)
- [管理工具](#管理工具)
- [API 文档](#api-文档)
- [性能优化](#性能优化)
- [安全建议](#安全建议)
- [故障排查](#故障排查)

---

## 功能特性

- 🛡️ **多种攻击防护**：SQL 注入、XSS、文件上传攻击、恶意爬虫等
- 🔄 **Redis 集成**：规则和配置存储在 Redis 中，支持动态热更新
- 💾 **本地缓存**：通过 ngx.shared 实现本地缓存，提升性能
- 👥 **IP 黑名单/白名单**：灵活的 IP 访问控制
- ⚡ **CC 防护**：防止恶意 CC 攻击
- 📊 **攻击日志**：记录详细的攻击日志
- 🎯 **多维度规则**：支持 URL、Args、POST、Cookie、User-Agent 等规则类型

---

## 快速开始

### 前置条件

- OpenResty 1.15.x+
- Redis 3.0+
- lua-resty-redis 模块（OpenResty 自带）
- **用于初始化脚本的可选依赖**：
  - 方式一：Python 3 + redis 模块（推荐，更通用）
  - 方式二：独立 Lua 解释器 + luasocket

检查是否已安装：

```bash
# 检查 OpenResty
/usr/local/openresty/bin/openresty -v

# 检查 Redis
redis-server -v
redis-cli ping

# 检查 Python（用于方式一）
python3 --version
pip3 --version
```

### 初始化脚本的前置说明

项目提供了两种初始化 Redis 数据的方式，根据你的环境选择其一：

| 方式 | 依赖 | 推荐场景 |
|------|------|---------|
| Python 脚本 | Python 3 + redis 模块 | 通用，推荐使用 |
| Lua 脚本 | 独立 Lua 解释器 + luasocket | 仅当有独立 Lua 环境时使用 |

**注意**：OpenResty 自带的 Lua 环境与独立的 Lua 解释器不同，OpenResty 的 LuaJIT 仅在 Nginx 进程内可用，不能直接在命令行运行 `lua` 命令。

---

#### 方式一：使用 Python 脚本（推荐）

安装依赖：

```bash
# 安装 Python redis 模块
pip3 install redis
```

#### 方式二：使用 Lua 脚本（仅当你有独立 Lua 环境时）

如果系统没有独立的 Lua 解释器，需要先安装：

```bash
# Ubuntu/Debian
apt-get install lua5.1 luarocks
luarocks install luasocket

# CentOS/RHEL
dnf -y install lua luarocks
luarocks install luasocket

# macOS (Homebrew)
brew install lua luarocks
luarocks install luasocket
```

### 两种使用模式

#### 模式一：原始文件模式（默认）

使用本地文件存储配置和规则，适合单实例部署。

#### 模式二：Redis 集中存储模式（新增）

使用 Redis 存储配置和规则，支持多实例共享、热更新。

---

### 5 分钟快速部署（Redis 模式）

#### 1️⃣ 安装文件

```bash
# 进入项目目录
cd /path/to/ngx_lua_waf

# 复制文件到 OpenResty 配置目录
mkdir -p /usr/local/openresty/nginx/conf/waf
cp *.lua /usr/local/openresty/nginx/conf/waf/
cp -r wafconf /usr/local/openresty/nginx/conf/waf/
cp -r admin /usr/local/openresty/nginx/conf/waf/
```

#### 2️⃣ 启用 Redis 模式

编辑 `/usr/local/openresty/nginx/conf/waf/config.lua`：

```lua
-- 将 use_redis 改为 true
use_redis = true

-- 如果 Redis 有密码，设置密码
redis_password = "your_redis_password_here"
```

#### 3️⃣ 配置 Nginx

在 nginx.conf 中添加以下配置（详细步骤请参考下方的"手把手配置 Nginx"章节）：

```nginx
http {
    lua_shared_dict limit 10m;
    lua_shared_dict waf_cache 10m;
    lua_package_path "/usr/local/openresty/nginx/conf/waf/?.lua;;";

    init_by_lua_block {
        require "init"
    }

    server {
        listen 80;
        server_name your-domain.com;  # 修改为你的域名或 IP

        access_by_lua_block {
            require "waf"
        }

        location / {
            root html;
            index index.html index.htm;
        }
    }
}
```

**详细的配置教程请继续阅读"手把手配置 Nginx"章节！**

#### 4️⃣ 启动 Redis

```bash
# 启动 Redis 服务
redis-server

# 或者使用 systemd
systemctl start redis
systemctl enable redis
```

#### 5️⃣ 初始化 Redis 数据

**推荐使用 Python 脚本**（更通用）：

```bash
cd /usr/local/openresty/nginx/conf/waf/admin

# 方式一：使用 Python 脚本（推荐）
# 确保已安装依赖：pip3 install redis
python3 init_redis.py
```

**仅当有独立 Lua 环境时使用 Lua 脚本**：

```bash
# 方式二：使用 Lua 脚本（需要独立 Lua 解释器）
# 确保已安装依赖：apt-get install lua5.1 luarocks && luarocks install luasocket
lua init_redis.lua
```

你会看到类似这样的输出：

```
正在初始化 Redis 数据...
Redis: 127.0.0.1:6379/0
[OK] 配置已初始化
[OK] url 规则已初始化 (XX 条)
[OK] args 规则已初始化 (XX 条)
[OK] post 规则已初始化 (XX 条)
[OK] cookie 规则已初始化 (XX 条)
[OK] user-agent 规则已初始化 (XX 条)
[OK] whiteurl 规则已初始化 (XX 条)
[OK] IP 白名单已初始化 (1 条)
[OK] IP 黑名单已初始化 (1 条)
[OK] 版本号已初始化

✅ Redis 数据初始化完成！
```

#### 6️⃣ 启动 OpenResty

```bash
# 测试配置
/usr/local/openresty/nginx/sbin/nginx -t

# 启动 OpenResty
/usr/local/openresty/nginx/sbin/nginx

# 如果已经启动，重新加载
/usr/local/openresty/nginx/sbin/nginx -s reload
```

---

### 验证 WAF 工作

#### 查看 WAF 信息

```bash
cd /usr/local/openresty/nginx/conf/waf/admin
lua waf-manager.lua info
```

#### 测试攻击拦截

使用 curl 测试 SQL 注入攻击是否被拦截：

```bash
# 测试 SQL 注入（应该被拦截，返回 403）
curl -v "http://localhost/?id=1' OR '1'='1"

# 测试 XSS 攻击（应该被拦截，返回 403）
curl -v "http://localhost/?q=<script>alert(1)</script>"

# 正常请求（应该通过，返回 200）
curl -v "http://localhost/"
```

如果 WAF 工作正常，攻击请求会返回 **403 Forbidden** 状态码，并显示拦截页面。

---

## 手把手配置 Nginx

本章节将详细讲解如何从零开始配置 Nginx，确保 WAF 正常工作。

### 步骤 1: 找到 nginx.conf 文件

通常 nginx.conf 位于以下位置：

```bash
# OpenResty 默认路径
/usr/local/openresty/nginx/conf/nginx.conf

# 或者通过以下命令查找
openresty -t
```

### 步骤 2: 备份原有配置

在修改之前，先备份原有配置：

```bash
cp /usr/local/openresty/nginx/conf/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf.backup
```

### 步骤 3: 编辑 nginx.conf

使用你喜欢的编辑器打开 nginx.conf：

```bash
vim /usr/local/openresty/nginx/conf/nginx.conf
# 或者
nano /usr/local/openresty/nginx/conf/nginx.conf
```

### 步骤 4: 在 http 块中添加 WAF 配置

找到 `http { ... }` 块，在其中添加以下配置：

```nginx
http {
    # ==================== 原有配置保持不变 ====================
    include       mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  logs/access.log  main;

    sendfile        on;
    tcp_nopush      on;
    tcp_nodelay     on;
    keepalive_timeout  65;

    # ==================== WAF 配置开始（添加这部分） ====================

    # 1. 定义共享内存字典 - 用于 CC 防护
    lua_shared_dict limit 10m;

    # 2. 定义共享内存字典 - 用于 WAF 本地缓存
    lua_shared_dict waf_cache 10m;

    # 3. Lua 模块搜索路径（根据你的实际安装路径修改）
    lua_package_path "/usr/local/openresty/nginx/conf/waf/?.lua;;";

    # 4. 在 init_by_lua 阶段加载 WAF 初始化
    init_by_lua_block {
        require "init"
    }

    # ==================== WAF 配置结束 ====================

    # ==================== 配置网站 server 块 ====================

    server {
        listen       80;
        server_name  your-domain.com;  # 修改为你的域名或 IP

        # ==================== WAF 检查（必须添加） ====================
        access_by_lua_block {
            require "waf"
        }
        # ==================== WAF 检查结束 ====================

        root   html;
        index  index.html index.htm;

        location / {
            try_files $uri $uri/ =404;
        }

        # 拒绝访问隐藏文件（可选）
        location ~ /\. {
            deny all;
            access_log off;
            log_not_found off;
        }
    }

    # ==================== HTTPS 网站配置（可选） ====================

    server {
        listen       443 ssl http2;
        server_name  secure.your-domain.com;

        # SSL 证书配置（请替换为你的证书路径）
        ssl_certificate      /path/to/your/cert.pem;
        ssl_certificate_key  /path/to/your/key.pem;

        ssl_session_cache    shared:SSL:10m;
        ssl_session_timeout  10m;

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;

        # ==================== WAF 检查 ====================
        access_by_lua_block {
            require "waf"
        }
        # ==================== WAF 检查结束 ====================

        root   html;
        index  index.html index.htm;

        location / {
            try_files $uri $uri/ =404;
        }
    }
}
```

### 步骤 5: 关键配置说明

| 配置项 | 说明 | 必须修改吗? |
|--------|------|-------------|
| `lua_shared_dict limit 10m` | CC 防护共享内存 | 否，默认 10m 即可 |
| `lua_shared_dict waf_cache 10m` | WAF 本地缓存 | 否，默认 10m 即可 |
| `lua_package_path` | Lua 模块路径 | **是**，根据你的安装路径修改 |
| `server_name` | 网站域名 | **是**，修改为你的域名或 IP |
| `access_by_lua_block` | WAF 检查代码 | **是**，必须添加 |

### 步骤 6: 验证配置文件

```bash
# 测试配置语法是否正确
/usr/local/openresty/nginx/sbin/nginx -t
```

如果看到以下输出，说明配置正确：

```
nginx: the configuration file /usr/local/openresty/nginx/conf/nginx.conf syntax is ok
nginx: configuration file /usr/local/openresty/nginx/conf/nginx.conf test is successful
```

### 步骤 7: 启动或重新加载 OpenResty

```bash
# 如果是第一次启动
/usr/local/openresty/nginx/sbin/nginx

# 如果已经在运行，重新加载配置
/usr/local/openresty/nginx/sbin/nginx -s reload
```

---

## 测试与验证

配置完成后，按照以下步骤测试 WAF 是否正常工作。

### 1. 测试前检查清单

在测试之前，确认以下各项：

- [ ] Redis 正在运行 (`redis-cli ping` 返回 PONG)
- [ ] Redis 数据已初始化 (`cd admin && lua waf-manager.lua info`)
- [ ] config.lua 中 `use_redis = true`
- [ ] nginx.conf 配置正确 (`nginx -t` 通过)
- [ ] OpenResty 已启动或重新加载

### 2. 使用 waf-manager 查看状态

```bash
cd /usr/local/openresty/nginx/conf/waf/admin
lua waf-manager.lua info
```

你应该看到 WAF 的运行状态信息。

### 3. 测试正常请求

首先测试正常请求是否能通过：

```bash
# 测试正常页面访问
curl -v "http://localhost/"

# 测试静态文件
curl -v "http://localhost/index.html"
```

**预期结果**: 返回 HTTP 200 OK，页面正常显示。

### 4. 测试 SQL 注入拦截

```bash
# 测试 1: 简单 SQL 注入
curl -v "http://localhost/?id=1' OR '1'='1"

# 测试 2: UNION 查询
curl -v "http://localhost/?id=1 UNION SELECT password FROM users"

# 测试 3: 注释注入
curl -v "http://localhost/?id=1' --"
```

**预期结果**: 返回 HTTP 403 Forbidden，被 WAF 拦截。

### 5. 测试 XSS 攻击拦截

```bash
# 测试 1: 简单 script 标签
curl -v "http://localhost/?q=<script>alert(1)</script>"

# 测试 2: img 标签 onerror
curl -v "http://localhost/?q=<img src=x onerror=alert(1)>"

# 测试 3: javascript 伪协议
curl -v "http://localhost/?q=<a href='javascript:alert(1)'>click</a>"
```

**预期结果**: 返回 HTTP 403 Forbidden，被 WAF 拦截。

### 6. 测试路径遍历攻击

```bash
# 测试 1: 访问 /etc/passwd
curl -v "http://localhost/?file=../../../../etc/passwd"

# 测试 2: Windows 路径遍历
curl -v "http://localhost/?file=..\..\..\windows\system32\drivers\etc\hosts"
```

**预期结果**: 返回 HTTP 403 Forbidden，被 WAF 拦截。

### 7. 测试恶意 User-Agent

```bash
# 测试 1: sqlmap
curl -v -H "User-Agent: sqlmap/1.0-dev (http://sqlmap.org)" http://localhost

# 测试 2: 扫描器
curl -v -H "User-Agent: Mozilla/5.0 (compatible; Nmap Scripting Engine)" http://localhost
```

**预期结果**: 返回 HTTP 403 Forbidden，被 WAF 拦截。

### 8. 测试 IP 黑名单/白名单

#### 8.1 添加测试 IP 到黑名单

```bash
cd /usr/local/openresty/nginx/conf/waf/admin

# 添加 192.168.1.100 到黑名单
lua waf-manager.lua ip blocklist add 192.168.1.100
```

#### 8.2 从黑名单 IP 测试访问

```bash
# 假设你的测试机器 IP 是 192.168.1.100
curl -v "http://localhost/"
```

**预期结果**: 返回 HTTP 403 Forbidden，被 WAF 拦截。

#### 8.3 将 IP 添加到白名单（绕过黑名单）

```bash
# 添加到白名单
lua waf-manager.lua ip whitelist add 192.168.1.100
```

#### 8.4 再次测试访问

```bash
curl -v "http://localhost/"
```

**预期结果**: 返回 HTTP 200 OK，白名单优先于黑名单。

### 9. 测试 CC 防护（可选）

#### 9.1 开启 CC 防护并设置较低的频率

```bash
cd /usr/local/openresty/nginx/conf/waf/admin

# 开启 CC 防护
lua waf-manager.lua config set CCDeny on

# 设置 CC 频率为 5次/60秒（方便测试）
lua waf-manager.lua config set CCrate 5/60
```

#### 9.2 快速发送多个请求

```bash
# 连续发送 10 个请求
for i in {1..10}; do curl -v "http://localhost/"; sleep 1; done
```

**预期结果**: 前 5 个请求正常，第 6 个及之后返回 HTTP 503 Service Unavailable。

#### 9.3 测试完成后恢复 CC 设置

```bash
# 关闭 CC 防护（或调大频率）
lua waf-manager.lua config set CCDeny off
```

### 10. 查看攻击日志

如果开启了攻击日志，可以查看拦截记录：

```bash
# 查看今天的攻击日志
tail -f /usr/local/openresty/nginx/logs/hack/$(hostname)_$(date +%Y-%m-%d)_sec.log
```

### 11. 测试完成检查清单

- [ ] 正常请求返回 200 OK
- [ ] SQL 注入请求返回 403
- [ ] XSS 攻击请求返回 403
- [ ] 路径遍历请求返回 403
- [ ] 恶意 User-Agent 返回 403
- [ ] IP 黑名单正常工作
- [ ] IP 白名单优先于黑名单
- [ ] CC 防护（如开启）正常工作
- [ ] 攻击日志正常记录

---

## 项目文件自检

在开始前，可以运行以下检查确保文件完整：

```bash
cd /path/to/ngx_lua_waf

echo "=== 检查核心文件 ==="
for f in waf.lua redis.lua cache.lua config.lua init.lua; do
  [ -f "$f" ] && echo "✓ $f" || echo "✗ $f 不存在"
done

echo -e "\n=== 检查管理工具 ==="
for f in admin/init_redis.lua admin/init_redis.py admin/waf-manager.lua; do
  [ -f "$f" ] && echo "✓ $f" || echo "✗ $f 不存在"
done

echo -e "\n=== 检查规则文件 ==="
for t in url args post cookie user-agent whiteurl; do
  [ -f "wafconf/$t" ] && echo "✓ wafconf/$t" || echo "✗ wafconf/$t 不存在"
done
```

---

## 架构设计

### 文件结构

```
ngx_lua_waf/
├── config.lua              # 主配置文件
├── waf.lua                 # WAF 核心逻辑
├── redis.lua               # Redis 操作模块
├── cache.lua               # 本地缓存模块
├── init.lua                # 初始化脚本
├── README.md               # 本文档
├── admin/
│   ├── init_redis.lua      # Redis 数据初始化 (Lua)
│   ├── init_redis.py       # Redis 数据初始化 (Python)
│   └── waf-manager.lua     # WAF 命令行管理工具
└── wafconf/                # 规则文件目录
    ├── url                 # URL 攻击规则
    ├── args                # GET 参数规则
    ├── post                # POST 参数规则
    ├── cookie              # Cookie 规则
    ├── user-agent          # User-Agent 规则
    └── whiteurl            # 白名单 URL
```

### 工作流程

```
请求进入
    ↓
IP 白名单检查 → 匹配 → 直接放行
    ↓ 不匹配
IP 黑名单检查 → 匹配 → 返回 403
    ↓ 不匹配
CC 防护检查 → 超限 → 返回 503
    ↓ 通过
白名单 URL 检查 → 匹配 → 直接放行
    ↓ 不匹配
URL 规则检查 → 匹配 → 拦截
    ↓ 不匹配
Args 规则检查 → 匹配 → 拦截
    ↓ 不匹配
User-Agent 规则检查 → 匹配 → 拦截
    ↓ 不匹配
Cookie 规则检查 → 匹配 → 拦截
    ↓ 不匹配
POST 规则检查 → 匹配 → 拦截
    ↓ 通过
正常放行
```

### Redis 数据结构

| Key | 类型 | 说明 |
|-----|------|------|
| `waf:config` | Hash | 运行时配置 |
| `waf:rules:url` | Set | URL 攻击规则 |
| `waf:rules:args` | Set | GET 参数规则 |
| `waf:rules:post` | Set | POST 参数规则 |
| `waf:rules:cookie` | Set | Cookie 规则 |
| `waf:rules:user-agent` | Set | User-Agent 规则 |
| `waf:rules:whiteurl` | Set | 白名单 URL |
| `waf:ip:whitelist` | Set | IP 白名单 |
| `waf:ip:blocklist` | Set | IP 黑名单 |
| `waf:cc:{ip}:{uri}` | String | CC 计数（带过期时间） |
| `waf:version:config` | String | 配置版本号 |
| `waf:version:rules` | String | 规则版本号 |
| `waf:version:ip` | String | IP 列表版本号 |

### 缓存机制

为了提高性能，系统采用双层缓存架构：

1. **Redis 持久化存储**：存储所有配置和规则
2. **ngx.shared 本地缓存**：每个 Worker 进程缓存一份数据，TTL 默认 5 秒
3. **版本号失效机制**：通过版本号控制缓存更新，避免频繁访问 Redis

---

## 配置说明

### config.lua 配置项

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `use_redis` | 是否使用 Redis 模式 | `false` |
| `redis_host` | Redis 服务器地址 | `127.0.0.1` |
| `redis_port` | Redis 端口 | `6379` |
| `redis_db` | Redis 数据库 | `0` |
| `redis_username` | Redis 6.0+ ACL 用户名 | `nil` |
| `redis_password` | Redis 密码 | `nil` |
| `redis_timeout` | 连接超时（毫秒） | `1000` |
| `redis_pool_size` | 连接池大小 | `100` |
| `redis_idle_timeout` | 空闲超时（毫秒） | `10000` |
| `cache_ttl` | 本地缓存 TTL（秒） | `5` |
| `enable_cache` | 是否启用本地缓存 | `true` |
| `attacklog` | 是否开启攻击日志 | `off` |
| `logdir` | 日志存储目录 | `/usr/local/openresty/nginx/logs/hack/` |
| `UrlDeny` | 是否开启 URL 检测 | `on` |
| `Redirect` | 攻击后是否重定向/拦截 | `on` |
| `CookieMatch` | 是否检测 Cookie | `on` |
| `postMatch` | 是否检测 POST 参数 | `on` |
| `whiteModule` | 是否启用白名单模块 | `on` |
| `CCDeny` | 是否开启 CC 防护 | `off` |
| `CCrate` | CC 防护频率（次/秒） | `100/60` |

### Redis 认证方式说明

| 认证方式 | redis_username | redis_password | 适用场景 |
|---------|---------------|----------------|---------|
| 无认证 | nil | nil | 本地测试环境 |
| 仅密码 | nil | "your_password" | Redis 5.x 及以下 |
| 用户名+密码 | "your_username" | "your_password" | Redis 6.0+ ACL |

### 运行时动态配置（Redis）

可以通过 Redis 动态修改配置，无需重启 Nginx：

```bash
# 开启攻击日志
redis-cli HSET waf:config attacklog on

# 开启 CC 防护
redis-cli HSET waf:config CCDeny on

# 设置 CC 频率限制为 50次/60秒
redis-cli HSET waf:config CCrate 50/60

# ⚠️ 重要：增加版本号触发本地缓存更新
redis-cli INCR waf:version:config
```

---

## 管理工具

### waf-manager.lua - 命令行管理工具

进入 admin 目录，使用 waf-manager.lua 进行管理：

```bash
cd /usr/local/openresty/nginx/conf/waf/admin
```

### 配置管理

| 操作 | 命令 |
|------|------|
| 查看所有配置 | `lua waf-manager.lua config list` |
| 获取单个配置 | `lua waf-manager.lua config get attacklog` |
| 设置配置 | `lua waf-manager.lua config set attacklog on` |

### 规则管理

| 操作 | 命令 |
|------|------|
| 列出 URL 规则 | `lua waf-manager.lua rule list url` |
| 列出 Args 规则 | `lua waf-manager.lua rule list args` |
| 列出 Post 规则 | `lua waf-manager.lua rule list post` |
| 添加 URL 规则 | `lua waf-manager.lua rule add url "evil\.php"` |
| 添加 Args 规则 | `lua waf-manager.lua rule add args "union.*select"` |
| 删除 URL 规则 | `lua waf-manager.lua rule del url "evil\.php"` |

### IP 管理

| 操作 | 命令 |
|------|------|
| 查看白名单 | `lua waf-manager.lua ip whitelist list` |
| 添加白名单 IP | `lua waf-manager.lua ip whitelist add 192.168.1.100` |
| 删除白名单 IP | `lua waf-manager.lua ip whitelist del 192.168.1.100` |
| 查看黑名单 | `lua waf-manager.lua ip blocklist list` |
| 添加黑名单 IP | `lua waf-manager.lua ip blocklist add 1.2.3.4` |
| 删除黑名单 IP | `lua waf-manager.lua ip blocklist del 1.2.3.4` |

### CC 防护管理

| 操作 | 命令 |
|------|------|
| 查看 CC 计数 | `lua waf-manager.lua cc status 192.168.1.100 /index.html` |
| 重置 CC 计数 | `lua waf-manager.lua cc reset 192.168.1.100 /index.html` |

### 其他命令

| 操作 | 命令 |
|------|------|
| 查看所有版本号 | `lua waf-manager.lua version` |
| 刷新所有版本号（触发缓存更新） | `lua waf-manager.lua flush` |
| 查看 WAF 完整信息 | `lua waf-manager.lua info` |

---

## API 文档

### redis.lua - Redis 操作模块

```lua
local waf_redis = require "redis"

-- ==================== 配置操作 ====================
waf_redis.get_config(key)              -- 获取单个配置
waf_redis.get_all_config()              -- 获取所有配置（返回 table）
waf_redis.set_config(key, value)        -- 设置配置（自动增加版本号）

-- ==================== 规则操作 ====================
waf_redis.get_rules(rule_type)          -- 获取规则（返回数组）
waf_redis.add_rule(rule_type, rule)     -- 添加规则（自动增加版本号）
waf_redis.del_rule(rule_type, rule)     -- 删除规则（自动增加版本号）
waf_redis.exists_rule(rule_type, rule)  -- 检查规则是否存在

-- ==================== IP 白名单 ====================
waf_redis.get_ip_whitelist()            -- 获取白名单列表
waf_redis.add_ip_whitelist(ip)          -- 添加白名单 IP
waf_redis.del_ip_whitelist(ip)          -- 删除白名单 IP
waf_redis.check_ip_whitelist(ip)        -- 检查 IP 是否在白名单

-- ==================== IP 黑名单 ====================
waf_redis.get_ip_blocklist()            -- 获取黑名单列表
waf_redis.add_ip_blocklist(ip)          -- 添加黑名单 IP
waf_redis.del_ip_blocklist(ip)          -- 删除黑名单 IP
waf_redis.check_ip_blocklist(ip)        -- 检查 IP 是否在黑名单

-- ==================== CC 防护 ====================
waf_redis.cc_incr(ip, uri, seconds)    -- CC 计数递增并设置过期时间
waf_redis.cc_get(ip, uri)               -- 获取当前 CC 计数

-- ==================== 版本管理 ====================
waf_redis.get_version(type)             -- 获取版本号
waf_redis.init_version(type)            -- 初始化版本号

-- ==================== 初始化操作 ====================
waf_redis.init_rules(rule_type, rules)  -- 批量初始化规则
waf_redis.init_ip_whitelist(ips)        -- 初始化白名单
waf_redis.init_ip_blocklist(ips)        -- 初始化黑名单
waf_redis.init_config(cfgs)             -- 初始化配置
```

### cache.lua - 本地缓存模块

```lua
local waf_cache = require "cache"

-- ==================== 基础缓存操作 ====================
waf_cache.get(key)                       -- 获取缓存
waf_cache.set(key, value, ttl)           -- 设置缓存
waf_cache.del(key)                       -- 删除缓存

-- ==================== 版本管理 ====================
waf_cache.get_version(type)              -- 获取缓存版本
waf_cache.set_version(type, version)     -- 设置缓存版本

-- ==================== 配置缓存 ====================
waf_cache.get_all_config()               -- 获取配置缓存
waf_cache.set_all_config(config)         -- 设置配置缓存

-- ==================== 规则缓存 ====================
waf_cache.get_rules(rule_type)           -- 获取规则缓存
waf_cache.set_rules(rule_type, rules)    -- 设置规则缓存

-- ==================== IP 列表缓存 ====================
waf_cache.get_ip_whitelist()             -- 获取白名单缓存
waf_cache.set_ip_whitelist(ips)          -- 设置白名单缓存
waf_cache.get_ip_blocklist()             -- 获取黑名单缓存
waf_cache.set_ip_blocklist(ips)          -- 设置黑名单缓存
waf_cache.check_ip_whitelist(ip)         -- 检查白名单缓存
waf_cache.check_ip_blocklist(ip)         -- 检查黑名单缓存

-- ==================== 其他操作 ====================
waf_cache.flush_all()                    -- 清空所有缓存
```

---

## 性能优化

### 1. 本地缓存调优

```lua
-- config.lua
cache_ttl = 10           -- 适当延长缓存时间（秒）
enable_cache = true       -- 确保启用缓存
```

### 2. Redis 连接池

```lua
-- config.lua
redis_pool_size = 100     -- 根据 Worker 数量调整
redis_idle_timeout = 10000 -- 空闲连接超时（毫秒）
```

### 3. 规则优化建议

- 规则数量控制在合理范围内（建议 < 1000 条）
- 优先使用精确匹配，减少复杂正则
- 将高频匹配的规则放在前面

### 4. Nginx Worker 配置

```nginx
worker_processes auto;  # 根据 CPU 核心数设置
```

---

## 安全建议

1. **保护 Redis**
   - 设置强密码
   - 绑定 127.0.0.1，不对外暴露
   - 禁用危险命令（CONFIG、FLUSHALL、FLUSHDB 等）
   - 使用 Redis ACL 限制权限

2. **定期更新规则**
   - 关注 CVE 和最新攻击向量
   - 定期更新规则库

3. **监控和日志**
   - 开启攻击日志：`redis-cli HSET waf:config attacklog on`
   - 定期分析攻击日志
   - 配置告警机制

4. **合理配置 CC 防护**
   - 根据业务情况设置合理的频率
   - 重要接口可以单独配置更严格的限制

5. **定期备份**
   - 定期备份 Redis 数据
   - 备份规则文件

---

## 故障排查

### 初始化脚本常见问题

#### 1. 运行 `lua init_redis.lua` 报错 "lua: command not found"

**原因**：系统没有安装独立的 Lua 解释器，或 OpenResty 的 Lua 环境不能直接在命令行使用。

**解决方法**：

**推荐方案 - 使用 Python 脚本**：
```bash
# 安装 Python redis 模块
pip3 install redis

# 使用 Python 脚本初始化
python3 init_redis.py
```

**如果必须使用 Lua 脚本**：
```bash
# Ubuntu/Debian
apt-get install lua5.1 luarocks
luarocks install luasocket

# CentOS/RHEL
yum install lua luarocks
luarocks install luasocket

# 然后再运行
lua init_redis.lua
```

#### 2. 运行 `python init_redis.py` 报错 "未安装 redis 模块"

**解决方法**：
```bash
# 安装 Python redis 模块
pip3 install redis

# 如果提示权限问题，使用 --user
pip3 install --user redis
```

#### 3. OpenResty 启动报错

**症状**：`systemctl restart openresty.service` 启动失败

**原因**：旧版 init.lua 在 init_by_lua 阶段尝试执行只能在请求阶段的代码（如 `io.open`, `ngx.var` 等）。

**解决方法**：
- 已在最新版本中修复了此问题，现在可以安全使用：

```nginx
# 在 nginx.conf 中添加：
init_by_lua_block {
    require "init"
}
```

**注意**：如果之前屏蔽 `init_by_lua_block` 只是为了避免启动报错，现在可以恢复即可。

---

### 常见问题

#### 1. Redis 连接失败

**症状**：Nginx 错误日志显示 "redis connect failed"

**排查步骤**：
```bash
# 检查 Redis 是否运行
redis-cli ping

# 检查配置
cat /usr/local/openresty/nginx/conf/waf/config.lua

# 测试连接
redis-cli -h 127.0.0.1 -p 6379
```

#### 2. 规则更新后不生效

**症状**：修改规则后，新规则没有生效

**解决方法**：
```bash
# 手动刷新版本号
cd /usr/local/openresty/nginx/conf/waf/admin
lua waf-manager.lua flush

# 或者使用 redis-cli
redis-cli INCR waf:version:rules
redis-cli INCR waf:version:config
```

#### 3. 正常请求被误拦截

**排查步骤**：
1. 查看攻击日志，确定是哪个规则拦截
2. 将误拦截的 URL 或 IP 加入白名单
3. 调整相关规则

```bash
# 查看攻击日志
tail -f /usr/local/openresty/nginx/logs/hack/$(hostname)_$(date +%Y-%m-%d)_sec.log

# 添加 URL 白名单
cd admin
lua waf-manager.lua rule add whiteurl "^/safe/path"

# 添加 IP 白名单
lua waf-manager.lua ip whitelist add 192.168.1.100
```

#### 4. 本地缓存问题

如果需要强制清除所有本地缓存，可以在 nginx.conf 中临时注释掉 `access_by_lua_block`，reload 后再恢复。

---

## 常见攻击测试

以下是一些测试命令，用于验证 WAF 是否正常工作：

```bash
# SQL 注入测试
curl "http://localhost/?id=1' OR '1'='1"
curl "http://localhost/?id=1 UNION SELECT password FROM users"

# XSS 测试
curl "http://localhost/?q=<script>alert(1)</script>"
curl "http://localhost/?q=<img src=x onerror=alert(1)>"

# 文件上传测试
curl -X POST -F "file=@evil.php" http://localhost/upload

# 路径遍历测试
curl "http://localhost/?file=../../../../etc/passwd"

# 恶意 User-Agent
curl -H "User-Agent: sqlmap/1.0-dev" http://localhost
```

---

## 快速开始（原始文件模式）

如果你想使用原始的文件模式，不使用 Redis，可以按照以下步骤操作：

### 1. 安装

```bash
cd /usr/local/openresty/nginx/conf
git clone https://github.com/linorwang/ngx_lua_waf.git waf
```

### 2. 配置 nginx.conf

在 `http` 块中添加：

```nginx
lua_package_path "/usr/local/openresty/nginx/conf/waf/?.lua;;";
lua_shared_dict limit 10m;
init_by_lua_file  /usr/local/openresty/nginx/conf/waf/init.lua;
access_by_lua_file /usr/local/openresty/nginx/conf/waf/waf.lua;
```

### 3. 配置 config.lua

```lua
use_redis = false  -- 确保关闭 Redis 模式
RulePath = "/usr/local/openresty/nginx/conf/waf/wafconf/"
attacklog = "off"
logdir = "/usr/local/openresty/nginx/logs/hack/"
UrlDeny = "on"
Redirect = "on"
CookieMatch = "on"
postMatch = "on"
whiteModule = "on"
CCDeny = "off"
CCrate = "100/60"
```

### 4. 重启 OpenResty

```bash
/usr/local/openresty/nginx/sbin/nginx -t
/usr/local/openresty/nginx/sbin/nginx -s reload
```

---

## 切换模式

### 从 Redis 模式回退到文件模式

在 `config.lua` 中设置：

```lua
use_redis = false
```

然后 reload OpenResty。

---

## 规则文件说明

规则文件位于 `wafconf/` 目录下：

| 文件 | 说明 |
|------|------|
| `args` | GET 参数过滤规则 |
| `url` | GET 请求 URL 过滤规则 |
| `post` | POST 请求过滤规则 |
| `cookie` | Cookie 过滤规则 |
| `user-agent` | User-Agent 过滤规则 |
| `whiteurl` | URL 白名单 |

---

## Copyright

| 项目 | 信息 |
|------|------|
| Weibo | 神奇的魔法师 |
| Forum | http://bbs.linuxtone.org/ |
| Copyright | Copyright (c) 2013- loveshell |
| License | MIT License |

感谢 ngx_lua 模块的开发者 [@agentzh](https://github.com/agentzh)

---

## 贡献

欢迎提交 Issue 和 Pull Request！

---

## 致谢

感谢所有为 WAF 安全做出贡献的开发者们！
