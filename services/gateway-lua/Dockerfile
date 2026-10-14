FROM openresty/openresty:1.29.2.5-alpine-fat

WORKDIR /opt/gateway

COPY tallowbrook-gateway-1.0-1.rockspec ./
RUN luarocks install --deps-only tallowbrook-gateway-1.0-1.rockspec

COPY conf/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /opt/gateway/lua/

EXPOSE 8080
CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]
