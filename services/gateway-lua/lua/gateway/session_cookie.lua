-- Encrypted session cookie (current format). Cookies in the old format are read once through
-- cookie_v1 and reissued in this one.
local aes = require "resty.aes"
local cjson = require "cjson.safe"
local config = require "gateway.config"
local cookie_v1 = require "gateway.cookie_v1"

local _M = {}

local box

local function cookie_box()
    if not box then
        box = assert(aes:new(config.session_secret,
            config.session_salt,
            aes.cipher(256, "cbc"),
            aes.hash.sha512, 5))
    end
    return box
end

local function urlsafe(b64)
    return (b64:gsub("[+/=]", { ["+"] = "-", ["/"] = "_", ["="] = "" }))
end

local function from_urlsafe(s)
    s = s:gsub("-", "+"):gsub("_", "/")
    return s .. string.rep("=", (4 - #s % 4) % 4)
end

function _M.encode(session)
    session.exp = ngx.time() + config.cookie_ttl
    local blob = cookie_box():encrypt(cjson.encode(session))
    return "2." .. urlsafe(ngx.encode_base64(blob))
end

function _M.decode(value)
    local body = value and value:match("^2%.(.+)$")
    if not body then
        return nil
    end
    local raw = ngx.decode_base64(from_urlsafe(body))
    local json = raw and cookie_box():decrypt(raw)
    local session = json and cjson.decode(json)
    if not session or (session.exp or 0) < ngx.time() then
        return nil
    end
    return session
end

local function set_cookie(value)
    ngx.header["Set-Cookie"] = string.format("%s=%s; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=%d",
        config.cookie_name, value, config.cookie_ttl)
end

-- access phase: put the customer id on the upstream request, upgrading v1 cookies on the way.
function _M.load()
    local session = _M.decode(ngx.var["cookie_" .. config.cookie_name])
    if not session then
        session = cookie_v1.read(ngx.var["cookie_" .. config.cookie_v1_name])
        if session then
            set_cookie(_M.encode(session))
        end
    end
    ngx.req.clear_header("X-Customer-Id")
    if session and session.customer_id then
        ngx.req.set_header("X-Customer-Id", session.customer_id)
    end
end

return _M
