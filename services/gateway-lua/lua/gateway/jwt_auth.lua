-- Partner calls carry a bearer token we issued them. The gateway checks it and swaps it for a
-- short-lived upstream token, so partner tokens never reach the backend.
local jwt = require "resty.jwt"
local config = require "gateway.config"

local _M = {}

function _M.upstream_token(partner_id)
    local now = ngx.time()
    return jwt:sign(config.upstream_secret, {
        header = { typ = "JWT", alg = config.jwt_alg },
        payload = {
            iss = config.token_issuer,
            sub = partner_id,
            iat = now,
            exp = now + config.upstream_token_ttl,
        },
    })
end

function _M.check_partner()
    local auth = ngx.var.http_authorization
    local token = auth and auth:match("^Bearer%s+(.+)$")
    if not token then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="partners"'
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    jwt:set_alg_whitelist({ HS256 = 1, HS512 = 1 })
    local verified = jwt:verify(config.partner_secret, token)
    if not verified.verified then
        ngx.log(ngx.INFO, "partner token rejected: ", verified.reason)
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    local partner_id = verified.payload and verified.payload.sub
    if type(partner_id) ~= "string" or partner_id == "" then
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end
    ngx.req.set_header("X-Partner-Id", partner_id)
    ngx.req.set_header("Authorization", "Bearer " .. _M.upstream_token(partner_id))
end

return _M
