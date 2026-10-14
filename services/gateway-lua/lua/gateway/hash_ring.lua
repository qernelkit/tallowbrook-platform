-- Consistent-hash ring for picking an upstream when a request needs to stick to one backend
-- (long-polling tracking updates). Plain round robin is used for everything else.
local _M = {}

local REPLICAS = 64
local ring = {}

function _M.build(nodes)
    ring = {}
    for _, node in ipairs(nodes) do
        for replica = 1, REPLICAS do
            local point = ngx.crc32_long(node .. "#" .. replica)
            ring[#ring + 1] = { point = point, node = node }
        end
    end
    table.sort(ring, function(a, b)
        return a.point < b.point
    end)
    return #ring
end

function _M.pick(point)
    local lo, hi = 1, #ring
    if hi == 0 then
        return nil
    end
    if point > ring[hi].point then
        return ring[1].node
    end
    while lo < hi do
        local mid = math.floor((lo + hi) / 2)
        if ring[mid].point < point then
            lo = mid + 1
        else
            hi = mid
        end
    end
    return ring[lo].node
end

-- Sticky by host for the tracking long-poll endpoint.
function _M.pick_by_host()
    if #ring == 0 then
        return nil
    end
    local slot = ngx.crc32_short(ngx.var.host) % #ring
    return ring[slot + 1].node
end

return _M
