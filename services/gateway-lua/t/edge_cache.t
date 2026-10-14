use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path "$prefix/../../lua/?.lua;;";
_EOC_

run_tests();

__DATA__

=== TEST 1: preview links bypass the cache
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            package.loaded["gateway.config"] = { cache_zone = "edge" }
            local cache = require "gateway.edge_cache"
            ngx.say(cache.bypass())
        }
    }
--- request
GET /t?preview=1
--- response_body
true

=== TEST 2: anonymous catalogue requests are cacheable
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            package.loaded["gateway.config"] = { cache_zone = "edge" }
            local cache = require "gateway.edge_cache"
            ngx.say(cache.bypass())
        }
    }
--- request
GET /t
--- response_body
false
