local config = require "config"

local _M = {}

local prometheus, metrics
local initialized, init_failed, failure_logged = false, false, false

local dict_name = config.prometheusMetricsDict or "prometheus_metrics"

local allowed = {
    outcome = {allow=true, block=true, skip=true, error=true},
    block = {
        url=true, args=true, post=true, cookie=true, ua=true, cmd=true,
        ssrf=true, pathtraversal=true, sensitivefile=true, webshell=true,
        file_ext=true, ip_blocklist=true, cc=true, body_too_large=true
    },
    rule = {
        url=true, args=true, post=true, cookie=true, ["user-agent"]=true,
        ua=true, cmd=true, ssrf=true, pathtraversal=true,
        sensitivefile=true, webshell=true, file_ext=true
    },
    cc = {limit_exceeded=true, ban_set=true, ban_hit=true},
    body = {too_large=true, read_failed=true},
    error = {run=true, redis=true, cache=true, regex=true, log_write=true, metrics=true},
    reload = {success=true, failure=true}
}

local function label(kind, value)
    value = tostring(value or "other")
    return allowed[kind] and allowed[kind][value] and value or "other"
end

local function log_failure(err)
    if failure_logged then return end
    failure_logged = true
    ngx.log(ngx.ERR, "[WAF] prometheus metrics unavailable: ", err or "-")
end

local function init()
    if initialized then return true end
    if init_failed then return false end
    if not ngx.shared or not ngx.shared[dict_name] then
        init_failed = true
        log_failure("missing lua_shared_dict "..dict_name)
        return false
    end

    local ok, prometheus_mod = pcall(require, "prometheus")
    if not ok then
        init_failed = true
        log_failure(prometheus_mod)
        return false
    end

    ok, prometheus = pcall(function() return prometheus_mod.init(dict_name) end)
    if not ok then
        init_failed = true
        log_failure(prometheus)
        return false
    end

    metrics = {
        requests = prometheus:counter(
            "waf_requests_total",
            "Total requests processed by the WAF.",
            {"outcome"}
        ),
        blocks = prometheus:counter(
            "waf_blocks_total",
            "Total requests blocked by the WAF.",
            {"reason"}
        ),
        rule_matches = prometheus:counter(
            "waf_rule_matches_total",
            "Total WAF rule matches.",
            {"type"}
        ),
        cc_events = prometheus:counter(
            "waf_cc_events_total",
            "Total WAF CC protection events.",
            {"event"}
        ),
        body_rejections = prometheus:counter(
            "waf_body_rejections_total",
            "Total request body rejections.",
            {"reason"}
        ),
        errors = prometheus:counter(
            "waf_errors_total",
            "Total WAF internal errors.",
            {"stage"}
        ),
        reloads = prometheus:counter(
            "waf_config_reload_total",
            "Total WAF configuration reload attempts.",
            {"result"}
        ),
        duration = prometheus:histogram(
            "waf_request_duration_seconds",
            "WAF request processing duration in seconds.",
            {"outcome"},
            {0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1}
        )
    }

    initialized = true
    return true
end

local function call_metric(fn)
    if not init() then return end
    local ok, err = pcall(fn)
    if not ok then log_failure(err) end
end

function _M.request(outcome, duration)
    outcome = label("outcome", outcome)
    call_metric(function()
        metrics.requests:inc(1, {outcome})
        if duration and duration >= 0 then
            metrics.duration:observe(duration, {outcome})
        end
    end)
end

function _M.block(reason)
    reason = label("block", reason)
    call_metric(function() metrics.blocks:inc(1, {reason}) end)
end

function _M.rule_match(rule_type)
    rule_type = label("rule", rule_type)
    call_metric(function() metrics.rule_matches:inc(1, {rule_type}) end)
end

function _M.cc_event(event)
    event = label("cc", event)
    call_metric(function() metrics.cc_events:inc(1, {event}) end)
end

function _M.body_rejection(reason)
    reason = label("body", reason)
    call_metric(function() metrics.body_rejections:inc(1, {reason}) end)
end

function _M.error(stage)
    stage = label("error", stage)
    call_metric(function() metrics.errors:inc(1, {stage}) end)
end

function _M.reload(result)
    result = label("reload", result)
    call_metric(function() metrics.reloads:inc(1, {result}) end)
end

function _M.collect()
    if not init() then
        ngx.status = ngx.HTTP_SERVICE_UNAVAILABLE or 503
        ngx.say("# WAF prometheus metrics unavailable")
        return
    end
    prometheus:collect()
end

return _M
