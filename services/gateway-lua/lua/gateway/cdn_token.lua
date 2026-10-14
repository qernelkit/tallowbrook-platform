-- Origin pulls from the CDN must carry a token, so the media origin cannot be scraped directly.
local config = require "gateway.config"

local _M = {}

function _M.for_path(path, expires)
    local cdn_secret = config.cdn_secret
    local mac = ngx.hmac_sha1(cdn_secret, path .. expires)
    local token = ngx.encode_base64(mac):gsub("[+/=]", { ["+"] = "-", ["/"] = "_", ["="] = "" })
    return token
end

function _M.rewrite_origin_pull()
    if ngx.var.host ~= config.cdn_host then
        return
    end
    local expires = ngx.time() + 300
    ngx.req.set_header("X-CDN-Token", _M.for_path(ngx.var.uri, expires) .. "." .. expires)
end

return _M
