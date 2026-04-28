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
    lua_shared_dict limit 10m;
    lua_shared_dict waf_cache 10m;
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

### 第四步：启用 Redis 模式

编辑 `/usr/local/openresty/nginx/conf/waf/config.lua`：

```lua
-- 改成 true
use_redis = true

-- 如果 Redis 有密码，在这里设置
redis_password = "your_redis_password"
```

### 第五步：初始化数据

```bash
# 进入管理目录
cd /usr/local/openresty/nginx/conf/waf/admin

# 安装 Python redis 模块
pip3 install redis

# 初始化 Redis 数据
python3 init_redis.py
```

看到 `✅ Redis 数据初始化完成！` 就成功了！

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
redis-cli HSET waf:config CCrate 100/60

# 新增防护功能开关配置
# 开启命令注入防护
redis-cli HSET waf:config CmdMatch on
# 开启 SSRF 防护
redis-cli HSET waf:config SSRFCheck on
# 开启路径遍历防护
redis-cli HSET waf:config PathTraversalCheck on
# 开启敏感文件防护
redis-cli HSET waf:config SensitiveFileCheck on
# 开启 Webshell 检测
redis-cli HSET waf:config WebshellCheck on

# ⚠️ 重要：修改配置后必须增加版本号，让 WAF 重新加载
redis-cli INCR waf:version:config
```

### 新增规则管理
```bash
# 查看命令注入规则
redis-cli SMEMBERS waf:rules:cmd
# 查看 SSRF 规则
redis-cli SMEMBERS waf:rules:ssrf
# 查看路径遍历规则
redis-cli SMEMBERS waf:rules:pathtraversal
# 查看敏感文件规则
redis-cli SMEMBERS waf:rules:sensitivefile
# 查看 Webshell 规则
redis-cli SMEMBERS waf:rules:webshell

# 添加新规则示例（以敏感文件为例）
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

# ⚠️ 重要：修改后增加版本号
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

### 规则管理
```bash
# 查看 URL 规则
redis-cli SMEMBERS waf:rules:url

# 查看 Args 规则
redis-cli SMEMBERS waf:rules:args

# 添加规则
redis-cli SADD waf:rules:url "evil\.php"

# 删除规则
redis-cli SREM waf:rules:url "evil\.php"

# ⚠️ 重要：修改后增加版本号
redis-cli INCR waf:version:rules
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
└── wafconf/            # 规则文件
    ├── url             # URL 拦截规则
    ├── args            # GET 参数规则
    ├── post            # POST 参数规则
    ├── cookie          # Cookie 规则
    ├── user-agent      # User-Agent 规则
    └── whiteurl        # 白名单 URL
```

---

## 🎯 功能特性

- ✅ SQL 注入防护
- ✅ XSS 跨站脚本防护
- ✅ 文件上传攻击防护
- ✅ 恶意爬虫拦截
- ✅ IP 黑名单/白名单
- ✅ CC 攻击防护
- ✅ Redis 集中管理，热更新规则
- ✅ 详细的攻击日志
- ✅ 命令注入防护（CmdMatch）
- ✅ SSRF 攻击防护（SSRFCheck）
- ✅ 路径遍历防护（PathTraversalCheck）
- ✅ 敏感文件访问防护（SensitiveFileCheck）
- ✅ Webshell 检测防护（WebshellCheck）

### 新增防护功能详细说明

- **CmdMatch（命令注入防护）**：检测并拦截 `&&`、`||`、`;`、`$()`、反引号等命令注入特征
- **SSRFCheck（SSRF 防护）**：检测并拦截内网地址请求，如 `127.0.0.1`、`192.168.x.x`、`10.x.x.x`、`172.16-31.x.x` 等
- **PathTraversalCheck（路径遍历防护）**：检测并拦截 `../`、`..\`、`%2e%2e%2f` 等路径遍历特征，以及 `/etc/passwd`、`/windows/system32`、`WEB-INF` 等敏感路径
- **SensitiveFileCheck（敏感文件防护）**：检测并拦截 `.git/`、`.env`、`phpinfo.php`、`.bak`、`.sql`、`.zip` 等敏感文件访问
- **WebshellCheck（Webshell 检测）**：检测并拦截 `eval()`、`assert()`、`system()`、`base64_decode()` 等危险函数调用

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

### 问题 3：规则不生效
刷新一下缓存：
```bash
redis-cli INCR waf:version:config
redis-cli INCR waf:version:rules
redis-cli INCR waf:version:ip
```

---

## 📄 License

MIT License

---

**就这么简单！快去试试吧！** 🚀
