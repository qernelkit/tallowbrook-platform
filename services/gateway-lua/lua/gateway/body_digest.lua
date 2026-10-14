-- Integrity header on requests we forward upstream (RFC 3230 style), so the API can reject a
-- body that was cut short between the edge and the backend.
local resty_sha256 = require "resty.sha256"

local _M = {}

function _M.header_for(body)
    local sha = resty_sha256:new()
    sha:update(body or "")
    return "SHA-256=" .. ngx.encode_base64(sha:final())
end

function _M.set_upstream_header()
    local method = ngx.req.get_method()
    if method ~= "POST" and method ~= "PUT" and method ~= "PATCH" then
        return
    end
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if body == nil and ngx.req.get_body_file() then
        ngx.log(ngx.WARN, "request body spilled to disk; no integrity header added")
        return
    end
    ngx.req.set_header("Digest", _M.header_for(body))
end

return _M
