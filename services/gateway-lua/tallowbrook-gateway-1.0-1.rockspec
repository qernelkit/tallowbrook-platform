rockspec_format = "3.0"
package = "tallowbrook-gateway"
version = "1.0-1"

source = {
   url = "git+https://git.tallowbrook.example/platform/gateway-lua.git",
   tag = "v1.0",
}

description = {
   summary = "Edge rules for the Tallowbrook public API (OpenResty)",
   homepage = "https://git.tallowbrook.example/platform/gateway-lua",
   license = "Proprietary",
}

dependencies = {
   "lua >= 5.1",
   "lua-resty-jwt == 0.3.2-1",
}

build = {
   type = "builtin",
   modules = {
      ["gateway.config"] = "lua/gateway/config.lua",
      ["gateway.session_cookie"] = "lua/gateway/session_cookie.lua",
      ["gateway.cookie_v1"] = "lua/gateway/cookie_v1.lua",
      ["gateway.body_digest"] = "lua/gateway/body_digest.lua",
      ["gateway.signed_urls"] = "lua/gateway/signed_urls.lua",
      ["gateway.attestation"] = "lua/gateway/attestation.lua",
      ["gateway.jwt_auth"] = "lua/gateway/jwt_auth.lua",
      ["gateway.edge_cache"] = "lua/gateway/edge_cache.lua",
      ["gateway.cdn_token"] = "lua/gateway/cdn_token.lua",
      ["gateway.trace_ids"] = "lua/gateway/trace_ids.lua",
      ["gateway.hash_ring"] = "lua/gateway/hash_ring.lua",
   },
}
