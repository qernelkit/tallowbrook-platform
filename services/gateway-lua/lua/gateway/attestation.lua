-- Edge attestation: the gateway signs a short statement about each request it forwards, so the
-- API can tell traffic that came through the edge from traffic that went around it. Each worker
-- makes its own key at start-up and publishes the public half at /internal/edge-keys.
local pkey = require "resty.openssl.pkey"

local _M = {}

local edge_key

local function key()
    if not edge_key then
        edge_key = assert(pkey.new({
            type = "EC",
            curve = "prime256v1",
        }))
        ngx.shared.gateway_cache:set("edge-key:" .. ngx.worker.id(), edge_key:to_PEM("public"))
    end
    return edge_key
end

function _M.statement(request_id, now)
    return table.concat({ ngx.req.get_method(), ngx.var.uri, request_id, tostring(now) }, "\n")
end

function _M.set_header()
    local request_id = ngx.var.request_id
    local now = ngx.time()
    local canonical = _M.statement(request_id, now)
    local sig = assert(key():sign(canonical, "sha256"))
    ngx.req.set_header("X-Edge-Attestation", table.concat({
        tostring(ngx.worker.id()), tostring(now), ngx.encode_base64(sig),
    }, "."))
end

return _M
