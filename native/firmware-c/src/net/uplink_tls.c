/*
 * Uplink TLS client. The gateway connects out to the cloud collector over TLS 1.3 only, pinned to
 * the depot root. mbedTLS does the handshake; telemetry and update checks ride this connection.
 */
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <stdlib.h>
#include <string.h>

#include "gateway/gw.h"
#include "gateway/gw_config.h"
#include "gateway/gw_log.h"
#include "gateway/gw_paths.h"
#include "gateway/telemetry.h"

/* TLS 1.3 suites the collector offers, most preferred first. */
static const int UPLINK_SUITES[] = { MBEDTLS_TLS1_3_AES_256_GCM_SHA384, MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256, 0 };

/* Key-exchange groups: X25519 first, then P-256 for the older collector. */
static const uint16_t UPLINK_GROUPS[] = { MBEDTLS_SSL_IANA_TLS_GROUP_X25519, MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1, MBEDTLS_SSL_IANA_TLS_GROUP_NONE };

struct gw_uplink {
    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt ca;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
};

int gw_uplink_connect(struct gw_uplink **out, const char *host, const char *port)
{
    struct gw_uplink *up = calloc(1, sizeof *up);
    if (up == NULL)
        return GW_ERR_IO;
    mbedtls_net_init(&up->net);
    mbedtls_ssl_init(&up->ssl);
    mbedtls_ssl_config_init(&up->conf);
    mbedtls_x509_crt_init(&up->ca);
    mbedtls_entropy_init(&up->entropy);
    mbedtls_ctr_drbg_init(&up->drbg);

    const char pers[] = "gwfw-uplink";
    int rc = mbedtls_ctr_drbg_seed(&up->drbg, mbedtls_entropy_func, &up->entropy, (const unsigned char *)pers,
                                   sizeof pers - 1);
    if (rc != 0 || mbedtls_x509_crt_parse_file(&up->ca, GW_TRUST_ANCHOR_PATH) != 0)
        goto fail;
    if (mbedtls_ssl_config_defaults(&up->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0)
        goto fail;

    mbedtls_ssl_conf_min_tls_version(&up->conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_ciphersuites(&up->conf, UPLINK_SUITES);
    mbedtls_ssl_conf_groups(&up->conf, UPLINK_GROUPS);
    mbedtls_ssl_conf_authmode(&up->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&up->conf, &up->ca, NULL);
    mbedtls_ssl_conf_rng(&up->conf, mbedtls_ctr_drbg_random, &up->drbg);

    if (mbedtls_ssl_setup(&up->ssl, &up->conf) != 0 || mbedtls_ssl_set_hostname(&up->ssl, host) != 0)
        goto fail;
    if (mbedtls_net_connect(&up->net, host, port, MBEDTLS_NET_PROTO_TCP) != 0) {
        GW_LOG_WARN("uplink: cannot reach %s:%s", host, port);
        goto fail;
    }
    mbedtls_ssl_set_bio(&up->ssl, &up->net, mbedtls_net_send, mbedtls_net_recv, NULL);

    rc = mbedtls_ssl_handshake(&up->ssl);
    if (rc != 0) {
        GW_LOG_WARN("uplink: handshake failed (-0x%04x)", (unsigned)-rc);
        goto fail;
    }
    if (mbedtls_ssl_get_verify_result(&up->ssl) != 0) {
        GW_LOG_WARN("uplink: collector certificate rejected");
        goto fail;
    }
    *out = up;
    return GW_OK;
fail:
    gw_uplink_close(up);
    return GW_ERR_IO;
}

int gw_uplink_send(struct gw_uplink *up, const uint8_t *data, size_t len)
{
    size_t off = 0;
    while (off < len) {
        int n = mbedtls_ssl_write(&up->ssl, data + off, len - off);
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (n <= 0)
            return GW_ERR_IO;
        off += (size_t)n;
    }
    return GW_OK;
}

void gw_uplink_close(struct gw_uplink *up)
{
    if (up == NULL)
        return;
    mbedtls_ssl_close_notify(&up->ssl);
    mbedtls_ssl_free(&up->ssl);
    mbedtls_ssl_config_free(&up->conf);
    mbedtls_x509_crt_free(&up->ca);
    mbedtls_ctr_drbg_free(&up->drbg);
    mbedtls_entropy_free(&up->entropy);
    mbedtls_net_free(&up->net);
    free(up);
}
