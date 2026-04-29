-- ==================== Redis 连接配置 ====================
use_redis = true

redis_host = "127.0.0.1"
redis_port = 6379
redis_db = 0  -- Redis DB 库选择，默认为 0
redis_username = "yanfa"  -- Redis 6.0+ ACL 用户名，没有则设为 nil
redis_password = "BTh44gxWmp6FjhR6"  -- 密码，没有则设为 nil
redis_timeout = 1000  -- 毫秒
redis_pool_size = 1000
redis_idle_timeout = 10000  -- 毫秒

-- ==================== 本地缓存配置 ====================
cache_ttl = 60  -- 秒，本地缓存过期时间
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
CmdMatch="on"
SSRFCheck="on"
PathTraversalCheck="on"
SensitiveFileCheck="on"
WebshellCheck="on"
ResponseFilter="off"
black_fileExt={"php","jsp"}
ipWhitelist={"127.0.0.1"}
ipBlocklist={"1.0.0.1","210.12.51.199"}
CCDeny="on"
CCrate="100/60"
CCBanTime=3600
html=[[
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>网站防火墙</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Hiragino Sans GB','Microsoft YaHei',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);background-size:400% 400%;animation:gradientBG 12s ease infinite;overflow:hidden;}
@keyframes gradientBG{0%{background-position:0% 50%;}50%{background-position:100% 50%;}100%{background-position:0% 50%;}}
.tear-left,.tear-right{position:fixed;top:0;width:50vw;height:100vh;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);background-size:400% 400%;animation:gradientBG 12s ease infinite;z-index:100;}
.tear-left{left:0;clip-path:polygon(0 0,100% 0,98% 5%,100% 10%,97% 15%,100% 20%,98% 25%,100% 30%,97% 35%,100% 40%,98% 45%,100% 50%,97% 55%,100% 60%,98% 65%,100% 70%,97% 75%,100% 80%,98% 85%,100% 90%,97% 95%,100% 100%,0 100%);animation:tearLeft 1.5s cubic-bezier(0.68,-0.55,0.265,1.55) 0.5s forwards,shake 0.1s ease-in-out 8 0.1s;}
.tear-right{right:0;clip-path:polygon(0 0,2% 5%,0 10%,3% 15%,0 20%,2% 25%,0 30%,3% 35%,0 40%,2% 45%,0 50%,3% 55%,0 60%,2% 65%,0 70%,3% 75%,0 80%,2% 85%,0 90%,3% 95%,0 100%,100% 100%,100% 0);animation:tearRight 1.5s cubic-bezier(0.68,-0.55,0.265,1.55) 0.5s forwards,shake 0.1s ease-in-out 8 0.1s;}
@keyframes shake{0%,100%{transform:translateX(0);}50%{transform:translateX(3px);}}
@keyframes tearLeft{0%{transform:translateX(0) rotate(0deg);}100%{transform:translateX(-120%) rotate(-5deg);filter:blur(2px);}}
@keyframes tearRight{0%{transform:translateX(0) rotate(0deg);}100%{transform:translateX(120%) rotate(5deg);filter:blur(2px);}}
.flash{position:fixed;inset:0;background:#fff;z-index:99;opacity:0;animation:flash 0.1s ease-out 0.5s;pointer-events:none;}
@keyframes flash{0%{opacity:0.8;}100%{opacity:0;}}
.box{width:100%;max-width:400px;background:rgba(255,255,255,0.95);backdrop-filter:blur(20px);border-radius:20px;box-shadow:0 20px 60px rgba(0,0,0,0.25);overflow:hidden;opacity:0;animation:slideUp 0.8s cubic-bezier(0.16,1,0.3,1) 1.6s forwards;position:relative;transition:all 0.3s cubic-bezier(0.4,0,0.2,1);}
.box:hover{transform:translateY(-4px);box-shadow:0 28px 80px rgba(0,0,0,0.3);background:rgba(255,255,255,1);}
.box:active{transform:translateY(-2px) scale(0.98);}
@keyframes slideUp{from{opacity:0;transform:translateY(40px) scale(0.95);box-shadow:0 10px 30px rgba(0,0,0,0.1);}to{opacity:1;transform:translateY(0) scale(1);box-shadow:0 20px 60px rgba(0,0,0,0.25);}}
.box::before{content:'';position:absolute;inset:0;padding:2px;border-radius:20px;background:linear-gradient(90deg,transparent 0%,rgba(255,255,255,0.3) 50%,transparent 100%);-webkit-mask:linear-gradient(#fff 0 0) content-box,linear-gradient(#fff 0 0);-webkit-mask-composite:xor;mask-composite:exclude;animation:shimmer 3.5s linear infinite;opacity:0.5;}
@keyframes shimmer{0%{transform:translateX(-100%);}100%{transform:translateX(100%);}}
.header{background:linear-gradient(135deg,#ff416c,#ff4b2b);padding:30px 25px;text-align:center;position:relative;overflow:hidden;}
.header::before{content:'';position:absolute;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(circle,rgba(255,255,255,0.15) 0%,transparent 70%);animation:pulse 3s ease-in-out infinite;}
@keyframes pulse{0%,100%{transform:scale(1);opacity:0.6;}50%{transform:scale(1.2);opacity:0.3;}}
.icon{width:60px;height:60px;margin:0 auto 15px;background:rgba(255,255,255,0.2);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:32px;animation:bounce 2s ease-in-out infinite 1.6s;position:relative;z-index:1;}
@keyframes bounce{0%,20%,50%,80%,100%{transform:translateY(0);}40%{transform:translateY(-10px);}60%{transform:translateY(-5px);}}
.header h1{margin:0;font-size:22px;color:#fff;position:relative;z-index:1;font-weight:700;letter-spacing:1px;text-shadow:0 2px 10px rgba(0,0,0,0.1);}
.content{padding:28px 25px;}
.warn{color:#e53e3e;font-weight:700;font-size:16px;margin-bottom:14px;display:flex;align-items:center;gap:8px;animation:fadeIn 0.6s ease 1.8s both;}
@keyframes fadeIn{from{opacity:0;transform:translateX(-10px);}to{opacity:1;transform:translateX(0);}}
.text{color:#2d3748;line-height:1.7;margin-bottom:20px;font-size:14px;animation:fadeIn 0.6s ease 1.9s both;}
.steps{background:linear-gradient(135deg,#fef5f5,#fff5f5);border-radius:12px;padding:18px;border:1px solid #fed7d7;animation:fadeIn 0.6s ease 2s both;}
.steps li{color:#c53030;margin:10px 0;list-style:none;padding-left:34px;position:relative;font-size:13.5px;line-height:1.6;transition:transform 0.2s ease;}
.steps li:hover{transform:translateX(5px);}
.steps li:before{content:'';position:absolute;left:8px;top:50%;transform:translateY(-50%);width:18px;height:18px;border-radius:50%;background:linear-gradient(135deg,#ff416c,#ff4b2b);display:flex;align-items:center;justify-content:center;color:#fff;font-size:11px;font-weight:700;}
.steps li:nth-child(1):before{content:'1';}
.steps li:nth-child(2):before{content:'2';}
.steps li:nth-child(3):before{content:'3';}
@media(prefers-color-scheme:dark){
.box{background:rgba(30,30,50,0.95);}
.text{color:#e2e8f0;}
}
@media(max-width:480px){
.box{max-width:100%;}
.header{padding:25px 18px;}
.header h1{font-size:20px;}
.icon{width:52px;height:52px;font-size:28px;}
.content{padding:24px 20px;}
}
</style>
</head>
<body>
<div class="tear-left"></div>
<div class="tear-right"></div>
<div class="flash"></div>
<div class="box">
<div class="header">
<div class="icon">🛡️</div>
<h1>WAF安全拦截</h1>
</div>
<div class="content">
<div class="warn">⚠️ 您的请求带有不合法参数，已被拦截！</div>
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
    CmdMatch = CmdMatch,
    SSRFCheck = SSRFCheck,
    PathTraversalCheck = PathTraversalCheck,
    SensitiveFileCheck = SensitiveFileCheck,
    WebshellCheck = WebshellCheck,
    ResponseFilter = ResponseFilter,
    black_fileExt = black_fileExt,
    ipWhitelist = ipWhitelist,
    ipBlocklist = ipBlocklist,
    CCDeny = CCDeny,
    CCrate = CCrate,
    CCBanTime = CCBanTime,
    html = html
}

return _M