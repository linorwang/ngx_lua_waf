# ngx_lua_waf

ngx_lua_waf 是一个基于 ngx_lua 的 Web 应用防火墙，使用简单、高性能、轻量级。

## 功能特性

- 防止 SQL 注入、本地包含、部分溢出、fuzzing 测试、XSS、SSRF 等 Web 攻击
- 防止 svn/备份之类文件泄漏
- 防止 ApacheBench 之类压力测试工具的攻击
- 屏蔽常见的扫描黑客工具、扫描器
- 屏蔽异常的网络请求
- 屏蔽图片附件类目录 PHP 执行权限
- 防止 webshell 上传

## 两种使用模式

### 模式一：原始文件模式（默认）

使用本地文件存储配置和规则，适合单实例部署。

### 模式二：Redis 集中存储模式（新增）

使用 Redis 存储配置和规则，支持多实例共享、热更新。

---

## 快速开始（原始文件模式）

### 1. 安装

假设 Nginx 安装路径为 `/usr/local/nginx/conf/`：

```bash
cd /usr/local/nginx/conf
git clone https://github.com/linorwang/ngx_lua_waf.git waf
```

### 2. 配置 nginx.conf

在 `http` 块中添加：

```nginx
lua_package_path "/usr/local/nginx/conf/waf/?.lua";
lua_shared_dict limit 10m;
init_by_lua_file  /usr/local/nginx/conf/waf/init.lua;
access_by_lua_file /usr/local/nginx/conf/waf/waf.lua;
```

### 3. 配置 config.lua

```lua
RulePath = "/usr/local/nginx/conf/waf/wafconf/"
attacklog = "off"  -- 默认关闭日志，需要时手动开启
logdir = "/usr/local/nginx/logs/hack/"
UrlDeny = "on"
Redirect = "on"
CookieMatch = "on"
postMatch = "on"
whiteModule = "on"
CCDeny = "off"
CCrate = "100/60"
```

### 4. 创建日志目录（如需启用日志）

```bash
mkdir -p /usr/local/nginx/logs/hack
chown -R nginx:nginx /usr/local/nginx/logs/hack
```

### 5. 重启 Nginx

```bash
nginx -t
nginx -s reload
```

---

## 快速开始（Redis 模式）

### 1. 前置条件

- Redis 服务
- lua-resty-redis 模块

### 2. 配置 nginx.conf

在 `http` 块中添加：

```nginx
lua_package_path "/usr/local/nginx/conf/waf/?.lua";
lua_shared_dict limit 50m;
lua_shared_dict waf_cache 10m;  # 新增，用于本地缓存
init_by_lua_file  /usr/local/nginx/conf/waf/init.lua;
access_by_lua_file /usr/local/nginx/conf/waf/waf.lua;
```

### 3. 配置 config.lua

```lua
-- ==================== Redis 连接配置 ====================
use_redis = true  -- 启用 Redis 版本

redis_host = "127.0.0.1"
redis_port = 6379
redis_db = 0  -- Redis DB 库选择，默认为 0
redis_username = nil  -- Redis 6.0+ ACL 用户名，没有则设为 nil
redis_password = nil  -- 密码，没有则设为 nil
redis_timeout = 1000  -- 毫秒
redis_pool_size = 100
redis_idle_timeout = 10000  -- 毫秒

-- ==================== 本地缓存配置 ====================
cache_ttl = 5  -- 秒，本地缓存过期时间
enable_cache = true  -- 是否启用本地缓存

-- ==================== WAF 基础配置（仅用于初始化 Redis，运行时从 Redis 读取） ====================
RulePath = "/usr/local/nginx/conf/waf/wafconf/"
attacklog = "off"  -- 默认关闭日志，需要时手动开启
logdir = "/usr/local/nginx/logs/hack/"  -- 日志存储目录，由维护者管理
UrlDeny="on"
Redirect="on"
CookieMatch="on"
postMatch="on"
whiteModule="on"
black_fileExt={"php","jsp"}
ipWhitelist={"127.0.0.1"}
ipBlocklist={"1.0.0.1"}
CCDeny="off"
CCrate="100/60"
```

#### Redis 配置项说明

| 配置项 | 说明 |
|--------|------|
| `redis_host` | Redis 主机地址 |
| `redis_port` | Redis 端口 |
| `redis_db` | Redis DB 库号，默认为 0 |
| `redis_username` | Redis 6.0+ ACL 用户名，没有则设为 nil |
| `redis_password` | Redis 密码，没有则设为 nil |
| `redis_timeout` | 连接超时时间（毫秒） |
| `redis_pool_size` | 连接池大小 |
| `redis_idle_timeout` | 连接空闲超时（毫秒） |

#### Redis 认证方式说明

| 认证方式 | redis_username | redis_password | 适用场景 |
|---------|---------------|----------------|---------|
| 无认证 | nil | nil | 本地测试环境 |
| 仅密码 | nil | "your_password" | Redis 5.x 及以下 |
| 用户名+密码 | "your_username" | "your_password" | Redis 6.0+ ACL |

### 4. 初始化 Redis 数据

使用 Python 脚本（推荐）：

```bash
cd /usr/local/nginx/conf/waf/admin
pip install redis
python3 init_redis.py
```

或使用 Lua 脚本（需要 luasocket）：

```bash
cd /usr/local/nginx/conf/waf/admin
lua init_redis.lua
```

### 5. 重启 Nginx

```bash
nginx -t
nginx -s reload
```

---

## 配置说明

### config.lua 配置项

| 配置项 | 说明 |
|--------|------|
| `RulePath` | 规则存放目录（仅文件模式） |
| `attacklog` | 是否开启攻击日志记录（默认 off） |
| `logdir` | 日志存储目录（由维护者管理） |
| `UrlDeny` | 是否拦截 URL 访问 |
| `Redirect` | 是否拦截后重定向 |
| `CookieMatch` | 是否拦截 Cookie 攻击 |
| `postMatch` | 是否拦截 POST 攻击 |
| `whiteModule` | 是否开启 URL 白名单 |
| `black_fileExt` | 禁止上传的文件后缀 |
| `ipWhitelist` | IP 白名单（仅文件模式） |
| `ipBlocklist` | IP 黑名单（仅文件模式） |
| `CCDeny` | 是否开启 CC 攻击拦截 |
| `CCrate` | CC 攻击频率（如 100/60 表示 60 秒内最多 100 次） |
| `html` | 拦截后显示的警告内容 |

---

## Redis 数据结构

```
waf:config                    (Hash)     # 配置
  ├─ attacklog
  ├─ logdir
  ├─ UrlDeny
  ├─ Redirect
  ├─ CookieMatch
  ├─ postMatch
  ├─ whiteModule
  ├─ CCDeny
  ├─ CCrate
  └─ html

waf:rules:url               (Set)      # URL 规则
waf:rules:args              (Set)      # ARGS 规则
waf:rules:post              (Set)      # POST 规则
waf:rules:cookie            (Set)      # Cookie 规则
waf:rules:user-agent        (Set)      # UA 规则
waf:rules:whiteurl          (Set)      # 白名单 URL

waf:ip:whitelist            (Set)      # IP 白名单
waf:ip:blocklist            (Set)      # IP 黑名单

waf:version:config          (String)   # 配置版本号
waf:version:rules           (String)   # 规则版本号
waf:version:ip              (String)   # IP 版本号

waf:cc:{ip}:{uri}           (String)   # CC 计数器（带过期时间）
```

---

## Redis 模式下的热更新

修改 Redis 数据后，递增对应的版本号即可自动生效，无需 reload Nginx：

```bash
# 修改配置后
redis-cli INCR waf:version:config

# 修改规则后
redis-cli INCR waf:version:rules

# 修改 IP 名单后
redis-cli INCR waf:version:ip
```

---

## Redis 模式常用命令

### 配置管理

```bash
# 修改单个配置
redis-cli HSET waf:config CCDeny on

# 查看所有配置
redis-cli HGETALL waf:config

# 开启日志
redis-cli HSET waf:config attacklog on
```

### 规则管理

```bash
# 添加规则
redis-cli SADD waf:rules:url "select.*from"

# 删除规则
redis-cli SREM waf:rules:url "select.*from"

# 查看所有规则
redis-cli SMEMBERS waf:rules:url

# 更新后递增版本号
redis-cli INCR waf:version:rules
```

### IP 名单管理

```bash
# 添加白名单 IP
redis-cli SADD waf:ip:whitelist 192.168.1.100

# 添加黑名单 IP
redis-cli SADD waf:ip:blocklist 10.0.0.1

# 检查 IP 是否在名单
redis-cli SISMEMBER waf:ip:whitelist 192.168.1.100

# 更新后递增版本号
redis-cli INCR waf:version:ip
```

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

## 检查规则是否生效

部署后测试：

```bash
curl http://your-domain/test.php?id=../etc/passwd
```

如果返回警告页面，说明规则生效。

注意：默认本机（127.0.0.1）在白名单中，不会被过滤。

---

## 切换模式

### 从 Redis 模式回退到文件模式

在 `config.lua` 中设置：

```lua
use_redis = false
```

然后 reload Nginx。

---

## 性能建议

1. **本地缓存 TTL**（Redis 模式）：建议 3-10 秒，平衡实时性和性能
2. **Redis 连接池**：根据 Nginx worker 数量调整 pool_size
3. **共享内存大小**：`waf_cache` 根据规则数量调整，建议 10-50m
4. **日志管理**：attacklog 默认关闭，按需开启，日志轮转和清理由维护者自行管理

---

## 文件结构

```
ngx_lua_waf/
├── config.lua              # 配置文件
├── init.lua                # 初始化脚本
├── init.lua.original       # 原始 init.lua（备份）
├── waf.lua                 # WAF 主逻辑
├── waf.lua.original        # 原始 waf.lua（备份）
├── redis.lua               # Redis 操作模块（新增）
├── cache.lua               # 本地缓存模块（新增）
├── README.md               # 本文档
├── install.sh
└── wafconf/                # 规则文件目录
    ├── args
    ├── cookie
    ├── post
    ├── url
    ├── user-agent
    └── whiteurl
└── admin/                  # 管理工具
    ├── init_redis.py       # Python 初始化脚本
    └── init_redis.lua      # Lua 初始化脚本
```

---

## 故障排查

### Redis 连接失败

检查：
- Redis 服务是否运行
- `config.lua` 中的连接配置是否正确
- 防火墙是否允许连接

### 认证失败

检查：
- 用户名和密码是否正确
- Redis 版本是否支持 ACL（如需用户名认证）
- Redis ACL 用户是否有足够权限

### 配置不生效

检查：
- 是否递增了版本号（Redis 模式）
- 本地缓存是否过期（等待 cache_ttl 秒）
- Nginx error.log 查看错误日志

---

## Copyright

| 项目 | 信息 |
|------|------|
| Weibo | 神奇的魔法师 |
| Forum | http://bbs.linuxtone.org/ |
| Copyright | Copyright (c) 2013- loveshell |
| License | MIT License |

感谢 ngx_lua 模块的开发者 [@agentzh](https://github.com/agentzh)
