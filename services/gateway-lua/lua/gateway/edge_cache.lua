-- Cache keys for catalogue pages. Merchants can ask support for a debug header to see why a
-- page was or was not served from the edge cache.
local cjson = require "cjson.safe"
local config = require "gateway.config"

local _M = {}

function _M.key()
    local cache_key = ngx.md5(ngx.var.host .. ngx.var.request_uri)
    local debug = { key = cache_key, host = ngx.var.host, uri = ngx.var.request_uri, zone = config.cache_zone }
    if ngx.var.http_x_cache_debug == "1" then
        ngx.header["X-Cache-Debug"] = ngx.encode_base64(cjson.encode(debug))
    end
    ngx.var.cache_key = cache_key
end

function _M.bypass()
    local args = ngx.req.get_uri_args()
    return args.preview ~= nil or ngx.var.cookie_tb_session ~= nil
end

return _M
