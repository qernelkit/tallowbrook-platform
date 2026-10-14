-- Download links for exports and invoices: /downloads/<path>?expires=<unix time>&sig=<hex>.
-- The API that hands out the links holds the same key.
local hmac = require "resty.hmac"
local str = require "resty.string"

local SIGNING_KEY_HEX = "a25399eb91320d6d432a7d3989281bad4e77b8b27c27a7869493104174f47814"

local function from_hex(hex)
    return (hex:gsub("..", function(pair)
        return string.char(tonumber(pair, 16))
    end))
end

local SIGNING_KEY = from_hex(SIGNING_KEY_HEX)

local _M = {}

local function constant_time_equal(a, b)
    if #a ~= #b then
        return false
    end
    local same = true
    for i = 1, #a do
        if a:byte(i) ~= b:byte(i) then
            same = false
        end
    end
    return same
end

function _M.check()
    local args = ngx.req.get_uri_args()
    local expires = tonumber(args.expires)
    local sig = type(args.sig) == "string" and args.sig:lower() or nil
    if not expires or not sig then
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    if expires < ngx.time() then
        return ngx.exit(ngx.HTTP_GONE)
    end

    local mac = hmac:new(SIGNING_KEY, hmac.ALGOS.SHA1)
    mac:update(ngx.var.uri .. "?expires=" .. expires)
    local expected = str.to_hex(mac:final())
    if not constant_time_equal(expected, sig) then
        ngx.log(ngx.INFO, "rejected download link for ", ngx.var.uri)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end

return _M
