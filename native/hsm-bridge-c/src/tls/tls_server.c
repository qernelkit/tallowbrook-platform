/*
 * The key custody listener. Every client presents a certificate from the issuing CA; the request
 * layer maps the certificate subject to a caller and its allowed verbs.
 */
#include "tls/tls_server.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "keyd/keyd.h"
#include "keyd/paths.h"
#include "keyd/tls_profile.h"
#include "util/log.h"

int keyd_tls_configure(SSL_CTX *ctx)
{
    const char *groups = getenv("KEYD_TLS_GROUPS");
    if (groups == NULL || *groups == '\0')
        groups = KEYD_TLS_GROUPS;
    else
        log_warn("listener: key exchange groups overridden from the environment: %s", groups);

    if (SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION) != 1) {
        log_openssl_errors("listener: protocol floor");
        return KEYD_ERR_LIB;
    }
    if (SSL_CTX_set1_groups_list(ctx, groups) != 1) {
        log_openssl_errors("listener: group list");
        return KEYD_ERR_LIB;
    }
    if (SSL_CTX_set_cipher_list(ctx, KEYD_TLS12_CIPHERS) != 1) {
        log_openssl_errors("listener: 1.2 suites");
        return KEYD_ERR_LIB;
    }
    if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256") != 1) {
        log_err("tls: cipher suite list rejected by the library");
        return KEYD_ERR_LIB;
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    return KEYD_OK;
}

int keyd_tls_load_identity(SSL_CTX *ctx)
{
    if (SSL_CTX_use_certificate_chain_file(ctx, KEYD_TLS_CERT_FILE) != 1
        || SSL_CTX_use_PrivateKey_file(ctx, KEYD_TLS_KEY_FILE, SSL_FILETYPE_PEM) != 1
        || SSL_CTX_check_private_key(ctx) != 1) {
        log_openssl_errors("listener: identity");
        return KEYD_ERR_IO;
    }
    if (SSL_CTX_load_verify_locations(ctx, KEYD_CLIENT_CA_FILE, NULL) != 1) {
        log_openssl_errors("listener: client CA");
        return KEYD_ERR_IO;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 3);
    return KEYD_OK;
}

SSL_CTX *keyd_tls_server_new(int load_identity)
{
    SSL_CTX *ctx = SSL_CTX_new_ex(NULL, NULL, TLS_server_method());
    if (ctx == NULL)
        return NULL;
    if (keyd_tls_configure(ctx) != KEYD_OK || (load_identity && keyd_tls_load_identity(ctx) != KEYD_OK)) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

/* ---- connections */

struct keyd_conn {
    SSL *ssl;
    int fd;
    char peer[128];
};

struct keyd_conn *keyd_conn_accept(SSL_CTX *ctx, int fd)
{
    struct keyd_conn *c = calloc(1, sizeof *c);
    if (c == NULL)
        return NULL;
    c->fd = fd;
    c->ssl = SSL_new(ctx);
    if (c->ssl == NULL || SSL_set_fd(c->ssl, fd) != 1 || SSL_accept(c->ssl) != 1) {
        log_openssl_errors("listener: accept");
        keyd_conn_close(c);
        return NULL;
    }
    X509 *cert = SSL_get0_peer_certificate(c->ssl);
    if (cert != NULL)
        X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, c->peer, sizeof c->peer);
    if (c->peer[0] == '\0') {
        log_warn("listener: client without a common name");
        keyd_conn_close(c);
        return NULL;
    }
    return c;
}

const char *keyd_conn_peer(const struct keyd_conn *c)
{
    return c->peer;
}

int keyd_conn_read(struct keyd_conn *c, void *buf, size_t cap, size_t *got)
{
    if (SSL_read_ex(c->ssl, buf, cap, got) == 1)
        return KEYD_OK;
    return SSL_get_error(c->ssl, 0) == SSL_ERROR_ZERO_RETURN ? KEYD_ERR_NOTFOUND : KEYD_ERR_IO;
}

int keyd_conn_write(struct keyd_conn *c, const void *buf, size_t len)
{
    size_t done = 0;
    return SSL_write_ex(c->ssl, buf, len, &done) == 1 && done == len ? KEYD_OK : KEYD_ERR_IO;
}

void keyd_conn_close(struct keyd_conn *c)
{
    if (c == NULL)
        return;
    if (c->ssl != NULL) {
        SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
    }
    if (c->fd >= 0)
        close(c->fd);
    free(c);
}
