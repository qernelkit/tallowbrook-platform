/* Listener context and connections. */
#ifndef KEYD_LISTENER_H
#define KEYD_LISTENER_H

#include <openssl/ssl.h>
#include <stddef.h>

int keyd_tls_configure(SSL_CTX *ctx);
int keyd_tls_load_identity(SSL_CTX *ctx);
SSL_CTX *keyd_tls_server_new(int load_identity);

struct keyd_conn;
struct keyd_conn *keyd_conn_accept(SSL_CTX *ctx, int fd);
const char *keyd_conn_peer(const struct keyd_conn *c);
int keyd_conn_read(struct keyd_conn *c, void *buf, size_t cap, size_t *got);
int keyd_conn_write(struct keyd_conn *c, const void *buf, size_t len);
void keyd_conn_close(struct keyd_conn *c);

#endif
