-- Gateway settings. Secrets come from the environment (see the env lines in nginx.conf).
local _M = {
    cookie_name = "tb_session",
    cookie_v1_name = "tbs",
    cookie_ttl = 8 * 3600,

    jwt_alg = "HS256",
    token_issuer = "https://edge.tallowbrook.example",
    upstream_token_ttl = 60,

    download_link_ttl = 900,
    cdn_host = "cdn.tallowbrook.example",
    cache_zone = "edge",
}

_M.session_secret = os.getenv("GATEWAY_SESSION_SECRET")
_M.session_salt = os.getenv("GATEWAY_SESSION_SALT")
_M.session_v1_secret = os.getenv("GATEWAY_SESSION_V1_SECRET")
_M.partner_secret = os.getenv("PARTNER_TOKEN_SECRET")
_M.upstream_secret = os.getenv("UPSTREAM_TOKEN_SECRET")
_M.cdn_secret = os.getenv("CDN_ORIGIN_SECRET")
_M.trace_id_start = tonumber(os.getenv("TRACE_ID_START") or "") or 0

for _, name in ipairs({ "session_secret", "partner_secret", "upstream_secret", "cdn_secret" }) do
    if not _M[name] or _M[name] == "" then
        error("gateway config: " .. name .. " is not set")
    end
end

if _M.session_salt and #_M.session_salt ~= 8 then
    error("gateway config: GATEWAY_SESSION_SALT must be exactly 8 characters")
end

return _M
