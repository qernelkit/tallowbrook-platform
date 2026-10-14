use Test::Nginx::Socket::Lua 'no_plan';

our $HttpConfig = <<'_EOC_';
    lua_package_path "$prefix/../../lua/?.lua;;";
_EOC_

run_tests();

__DATA__

=== TEST 1: every node gets points on the ring
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local ring = require "gateway.hash_ring"
            ngx.say(ring.build({ "a:1", "b:1", "c:1" }))
        }
    }
--- request
GET /t
--- response_body
192

=== TEST 2: the same point always picks the same node
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local ring = require "gateway.hash_ring"
            ring.build({ "a:1", "b:1", "c:1" })
            ngx.say(ring.pick(12345) == ring.pick(12345))
        }
    }
--- request
GET /t
--- response_body
true

=== TEST 3: an empty ring picks nothing
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
            local ring = require "gateway.hash_ring"
            ring.build({})
            ngx.say(tostring(ring.pick(1)))
        }
    }
--- request
GET /t
--- response_body
nil
