# ngx_lua_waf Redis 版本

基于 Redis 的高可用 Web 应用防火墙，支持多台 Nginx+Keepalived 部署环境下的数据共享。

## 架构改进

### 原架构问题
- 单机文件存储，规则和配置无法在多台 Nginx 间同步
- IP 黑白名单、CC 防护数据仅存在本地共享内存
- 规则更新需要重启所有 Nginx 节点

### 新架构优势
- Redis 集中存储配置、规则、IP 黑白名单、CC 防护数据
- 支持动态更新，无需重启 Nginx
- 多节点数据实时同步
- 本地缓存 + Redis 双层架构，保证性能

## Redis 数据结构设计

### 1. 配置存储 (Hash)
```
key: waf:config
field: RulePath, attacklog, logdir, UrlDeny, Redirect, CookieMatch, postMatch, whiteModule, CCDeny, CCrate, html
```

### 2. 规则存储 (Set/List)
```
# URL 规则
key: waf:rules:url
type: set

# ARGS 规则
key: waf:rules:args
type: set

# POST 规则
key: waf:rules:post
type: set

# COOKIE 规则
key: waf:rules:cookie
type: set

# USER-AGENT 规则
key: waf:rules:user-agent
type: set

# 白名单 URL
key: waf:rules:whiteurl
type: set
```

### 3. IP 黑白名单 (Set)
```
# IP 白名单
key: waf:ip:whitelist
type: set

# IP 黑名单
key: waf:ip:blocklist
type: set
```

### 4. CC 防护 (Hash + Expire)
```
# CC 计数
key: waf:cc:{ip}:{uri}
type: string
expire: 根据 CCrate 配置
```

### 5. 本地缓存版本控制 (String)
```
# 配置版本
key: waf:version:config
type: string

# 规则版本
key: waf:version:rules
type: string

# IP 名单版本
key: waf:version:ip
type: string
```

## 文件结构

```
ngx_lua_waf/
├── config.lua              # 基础配置（Redis 连接等）
├── config-redis.lua        # Redis 配置管理模块
├── init.lua                # 初始化文件
├── waf.lua                 # 主逻辑文件
├── redis.lua               # Redis 操作封装
├── cache.lua               # 本地缓存管理
├── README.md               # 原文档
├── README-REDIS.md         # 本文档
├── install.sh              # 安装脚本
├── wafconf/                # 规则文件（保留作为初始化用）
└── admin/                  # 管理工具
    ├── init_redis.lua      # 初始化 Redis 数据
    └── manage.lua          # 规则管理脚本
```

## 安装部署

### 1. 前置要求
- Nginx + ngx_lua 模块
- LuaJIT 2.1+
- Redis 5.0+
- lua-resty-redis 库

### 2. 安装 lua-resty-redis
```bash
cd /usr/local/src
git clone https://github.com/openresty/lua-resty-redis.git
cp -r lua-resty-redis/lib/resty /usr/local/nginx/conf/waf/
```

### 3. Nginx 配置
```nginx
http {
    lua_package_path "/usr/local/nginx/conf/waf/?.lua;;";
    lua_shared_dict limit 10m;
    lua_shared_dict waf_cache 50m;  # 新增：本地缓存共享内存
    
    init_by_lua_file  /usr/local/nginx/conf/waf/init.lua; 
    access_by_lua_file /usr/local/nginx/conf/waf/waf.lua;
}
```

### 4. 初始化 Redis 数据
```bash
cd /usr/local/nginx/conf/waf/admin
lua init_redis.lua
```

## 配置说明

### config.lua 配置项
```lua
-- Redis 连接配置
redis_host = "127.0.0.1"
redis_port = 6379
redis_password = nil
redis_timeout = 1000  -- 毫秒
redis_pool_size = 100
redis_idle_timeout = 10000  -- 毫秒

-- 本地缓存配置
cache_ttl = 5  -- 秒，本地缓存过期时间
enable_cache = true  -- 是否启用本地缓存
```

## 管理工具使用

### 初始化 Redis
```bash
cd admin
lua init_redis.lua
```

### 添加规则
```bash
# 添加 URL 规则
lua manage.lua add url "\.bak$"

# 添加 IP 到白名单
lua manage.lua whitelist add 192.168.1.100

# 添加 IP 到黑名单
lua manage.lua blocklist add 10.0.0.1
```

### 删除规则
```bash
# 删除 URL 规则
lua manage.lua del url "\.bak$"

# 从白名单删除 IP
lua manage.lua whitelist del 192.168.1.100
```

### 查看规则
```bash
# 查看所有 URL 规则
lua manage.lua list url

# 查看白名单
lua manage.lua whitelist list
```

### 更新配置
```bash
# 开启攻击日志
lua manage.lua config attacklog on

# 设置 CC 频率
lua manage.lua config CCrate "200/60"
```

## 性能优化

1. **本地缓存策略**
   - 配置和规则在本地有缓存，默认 5 秒过期
   - 通过版本号机制，Redis 更新后主动失效本地缓存

2. **Redis 连接池**
   - 使用 cosocket 连接池，复用连接

3. **Pipeline 操作**
   - 批量读取规则时使用 pipeline 减少网络开销

## 与 Keepalived 配合

在 Keepalived 集群环境中：

1. **Redis 部署**
   - 建议 Redis 也采用主从复制 + Sentinel 高可用
   - 或使用 Redis Cluster

2. **配置同步**
   - 所有 Nginx 节点连接同一个 Redis
   - 规则更新后所有节点实时生效

3. **故障转移**
   - Nginx 故障不影响数据
   - Redis 故障时可降级使用本地缓存

## 回退方案

如果需要回退到文件版本：

1. 恢复原始的 init.lua 和 waf.lua
2. 注释掉 nginx.conf 中的 waf_cache 共享内存
3. 重启 Nginx

## License

MIT License
