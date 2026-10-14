-- Reads session cookies in the v1 format (before March 2025) so signed-in customers are not
-- logged out by the switch. Removed once the last v1 cookies have expired.
local aes = require "resty.aes"
local cjson = require "cjson.safe"
local config = require "gateway.config"

local _M = {}

local v1_box

function _M.read(value)
    if not value or value == "" or not config.session_v1_secret then
        return nil
    end
    if not v1_box then
        local v1_key = config.session_v1_secret
        v1_box = aes:new(v1_key)
    end
    local raw = ngx.decode_base64(ngx.unescape_uri(value))
    local json = raw and v1_box:decrypt(raw)
    local data = json and cjson.decode(json)
    if type(data) ~= "table" or not data.uid then
        return nil
    end
    return { customer_id = data.uid, locale = data.lang or "en" }
end

return _M
