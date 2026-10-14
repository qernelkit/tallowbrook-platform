use Test::Nginx::Socket::Lua 'no_plan';

run_tests();

__DATA__

=== TEST 1: health check answers without touching the backend
--- config
    location = /healthz {
        access_log off;
        content_by_lua_block { ngx.say("ok") }
    }
--- request
GET /healthz
--- response_body
ok
--- no_error_log
[error]
