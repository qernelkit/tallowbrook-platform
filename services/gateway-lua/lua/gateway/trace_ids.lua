-- Internal trace ids include the backend host and a sequence number. Responses carry them in an
-- opaque form; support turns them back with reveal() when a customer quotes one.
local bit = require "bit"
local config = require "gateway.config"

local _M = {}

local function roll(bytes)
    local k = config.trace_id_start % 256
    local out = {}
    for i = 1, #bytes do
        out[i] = string.char(bit.bxor(bytes:byte(i), k))
        k = (k * 31 + i) % 256
    end
    return table.concat(out)
end

function _M.obscure(id)
    return (ngx.encode_base64(roll(id)):gsub("=+$", ""))
end

function _M.reveal(masked)
    local padded = masked .. string.rep("=", (4 - #masked % 4) % 4)
    local raw = ngx.decode_base64(padded)
    return raw and roll(raw) or nil
end

-- header filter: replace the backend's trace id before the response leaves the edge.
function _M.rewrite_response_header()
    local id = ngx.header["X-Trace-Id"]
    if type(id) == "string" and id ~= "" then
        ngx.header["X-Trace-Id"] = _M.obscure(id)
    end
end

return _M
