/*
 * Gate passes for hauliers: a QR code on the driver's phone or a printed slip, scanned by the yard
 * gate reader. The reader has the yard's public key and checks the pass offline, so the signature
 * has to be small enough for a QR code. Payload and signature are Base45-encoded (RFC 9285) for the
 * alphanumeric QR mode.
 */
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keyd/crypto_api.h"
#include "keyd/keyd.h"
#include "util/crypto_util.h"
#include "util/log.h"

#define PASS_PAYLOAD_MAX 128
#define SECRET_FILE "gatepass.sk"
#define PUBLIC_FILE "gatepass.pk"

static const char BASE45[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

static OQS_SIG *gatepass_scheme(void)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (sig == NULL)
        log_err("gatepass: signature method not available in this liboqs build");
    return sig;
}

static size_t base45_encode(char *out, size_t cap, const unsigned char *in, size_t len)
{
    size_t n = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        unsigned int v = (unsigned int)in[i] * 256 + in[i + 1];
        if (n + 3 >= cap)
            return 0;
        out[n++] = BASE45[v % 45];
        out[n++] = BASE45[(v / 45) % 45];
        out[n++] = BASE45[v / 2025];
    }
    if (len % 2 == 1) {
        unsigned int v = in[len - 1];
        if (n + 2 >= cap)
            return 0;
        out[n++] = BASE45[v % 45];
        out[n++] = BASE45[v / 45];
    }
    out[n] = '\0';
    return n;
}

static void path_in(char *buf, size_t cap, const char *dir, const char *name)
{
    snprintf(buf, cap, "%s/%s", dir, name);
}

int keyd_gatepass_new_key(const char *dir)
{
    char path[512];
    OQS_SIG *sig = gatepass_scheme();
    if (sig == NULL)
        return KEYD_ERR_LIB;

    unsigned char *pk = malloc(sig->length_public_key);
    unsigned char *sk = malloc(sig->length_secret_key);
    int rc = KEYD_ERR_NOMEM;
    if (pk == NULL || sk == NULL)
        goto out;
    rc = KEYD_ERR_LIB;
    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS)
        goto out;

    path_in(path, sizeof path, dir, SECRET_FILE);
    rc = keyd_write_file(path, sk, sig->length_secret_key, 0600);
    if (rc == KEYD_OK) {
        path_in(path, sizeof path, dir, PUBLIC_FILE);
        rc = keyd_write_file(path, pk, sig->length_public_key, 0644);
    }
    if (rc == KEYD_OK)
        log_info("gatepass: new yard key written; distribute %s to the gate readers", path);
out:
    if (sk != NULL)
        crypto_wipe(sk, sig->length_secret_key);
    free(sk);
    free(pk);
    OQS_SIG_free(sig);
    return rc;
}

static int pass_payload(const struct gate_pass *gp, char *out, size_t cap)
{
    int n = snprintf(out, cap, "TBGP1|%s|%s|%u|%lld|%lld", gp->plate, gp->depot, (unsigned)gp->dock,
                     (long long)gp->not_before, (long long)gp->not_after);
    return n > 0 && (size_t)n < cap ? n : -1;
}

int keyd_gatepass_issue(const struct gate_pass *gp, const char *dir, char *qr, size_t qr_cap)
{
    char payload[PASS_PAYLOAD_MAX], path[512];
    struct keyd_buf sk = { 0 };
    unsigned char *blob = NULL;
    int rc;

    if (gp->not_after <= gp->not_before || gp->not_after - gp->not_before > 2 * 86400)
        return KEYD_ERR_POLICY;
    int plen = pass_payload(gp, payload, sizeof payload);
    if (plen < 0)
        return KEYD_ERR_ARGS;

    OQS_SIG *sig = gatepass_scheme();
    if (sig == NULL)
        return KEYD_ERR_LIB;
    path_in(path, sizeof path, dir, SECRET_FILE);
    if ((rc = keyd_read_file(path, 16 * 1024, &sk)) != KEYD_OK || sk.len != sig->length_secret_key) {
        rc = rc == KEYD_OK ? KEYD_ERR_ARGS : rc;
        goto out;
    }

    blob = malloc((size_t)plen + 2 + sig->length_signature);
    if (blob == NULL) {
        rc = KEYD_ERR_NOMEM;
        goto out;
    }
    size_t sig_len = 0;
    memcpy(blob, payload, (size_t)plen);
    if (OQS_SIG_sign(sig, blob + plen + 2, &sig_len, (const uint8_t *)payload, (size_t)plen, sk.data) != OQS_SUCCESS) {
        rc = KEYD_ERR_LIB;
        goto out;
    }
    blob[plen] = (unsigned char)(sig_len >> 8);
    blob[plen + 1] = (unsigned char)sig_len;
    rc = base45_encode(qr, qr_cap, blob, (size_t)plen + 2 + sig_len) > 0 ? KEYD_OK : KEYD_ERR_ARGS;
out:
    keyd_buf_free(&sk);
    free(blob);
    OQS_SIG_free(sig);
    return rc;
}
