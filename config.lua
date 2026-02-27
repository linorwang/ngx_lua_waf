-- ==================== Redis 连接配置 ====================
use_redis = true

redis_host = "172.26.253.215"
redis_port = 6379
redis_db = 0  -- Redis DB 库选择，默认为 0
redis_username = "yanfa"  -- Redis 6.0+ ACL 用户名，没有则设为 nil
redis_password = "BTh44gxWmp6FjhR6"  -- 密码，没有则设为 nil
redis_timeout = 1000  -- 毫秒
redis_pool_size = 100
redis_idle_timeout = 10000  -- 毫秒

-- ==================== 本地缓存配置 ====================
cache_ttl = 5  -- 秒，本地缓存过期时间
enable_cache = true  -- 是否启用本地缓存

-- ==================== WAF 基础配置（仅用于初始化 Redis，运行时从 Redis 读取） ====================
RulePath = "/usr/local/openresty/nginx/conf/waf/wafconf/"
attacklog = "off"  -- 默认关闭日志，需要时手动开启
logdir = "/usr/local/openresty/nginx/logs/hack/"  -- 日志存储目录，由维护者管理
UrlDeny="on"
Redirect="on"
CookieMatch="on"
postMatch="on" 
whiteModule="on" 
black_fileExt={"php","jsp"}
ipWhitelist={"127.0.0.1"}
ipBlocklist={"1.0.0.1","210.12.51.197"}
CCDeny="on"
CCrate="10/60"
html=[[
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>网站防火墙</title>
<style>
body{font-family:Microsoft YaHei, sans-serif;background:#f0f2f5;margin:0;padding:50px 20px;}
.box{max-width:500px;margin:0 auto;background:#fff;border-radius:10px;box-shadow:0 4px 20px rgba(0,0,0,0.1);overflow:hidden;}
.header{background:linear-gradient(135deg,#ffc107,#ff9800);color:#333;padding:30px;text-align:center;}
.header h1{margin:0;font-size:22px;}
.content{padding:30px;}
.warn{color:#e53e3e;font-weight:600;font-size:16px;margin-bottom:15px;}
.text{color:#4a5568;line-height:1.8;margin-bottom:20px;}
.steps{background:#fff3cd;border-radius:8px;padding:20px;border:1px solid #ffc107;}
.steps li{color:#856404;margin:10px 0;list-style:none;padding-left:20px;position:relative;}
.steps li:before{content:"•";color:#ff9800;position:absolute;left:5px;font-weight:700;}
</style>
</head>
<body>
<div class="box">
<div class="header"><h1>⚠️ 网站防火墙</h1></div>
<div class="content">
<div class="warn">您的请求带有不合法参数，已被拦截！</div>
<div class="text">可能原因：您提交的内容包含危险的攻击请求</div>
<div class="steps">
<li>检查提交内容</li>
<li>如网站托管，请联系空间提供商</li>
<li>普通网站访客，请联系网站管理员</li>
</div>
</div>
</div>
</body>
</html>
]]

local _M = {
    use_redis = use_redis,
    redis_host = redis_host,
    redis_port = redis_port,
    redis_db = redis_db,
    redis_username = redis_username,
    redis_password = redis_password,
    redis_timeout = redis_timeout,
    redis_pool_size = redis_pool_size,
    redis_idle_timeout = redis_idle_timeout,
    cache_ttl = cache_ttl,
    enable_cache = enable_cache,
    RulePath = RulePath,
    attacklog = attacklog,
    logdir = logdir,
    UrlDeny = UrlDeny,
    Redirect = Redirect,
    CookieMatch = CookieMatch,
    postMatch = postMatch,
    whiteModule = whiteModule,
    black_fileExt = black_fileExt,
    ipWhitelist = ipWhitelist,
    ipBlocklist = ipBlocklist,
    CCDeny = CCDeny,
    CCrate = CCrate,
    html = html
}

return _M
