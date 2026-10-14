/*
 * Start-up self-check. Runs before the daemon opens its listener (ExecStartPre=tbkeyd --self-check)
 * so that a library upgrade that drops something tbkeyd depends on is caught before clients are
 * refused. Uses throwaway keys and a scratch directory only.
 */
#include "selfcheck.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "keyd/algorithms.h"
#include "keyd/audit.h"
#include "keyd/crypto_api.h"
#include "keyd/export.h"
#include "keyd/keyd.h"
#include "keyd/link.h"
#include "tls/tls_server.h"
#include "util/crypto_util.h"

static int failures;

static void report(const char *what, int rc)
{
    printf("%s %s%s%s\n", rc == KEYD_OK ? "ok  " : "FAIL", what, rc == KEYD_OK ? "" : ": ",
           rc == KEYD_OK ? "" : keyd_status_str(rc));
    if (rc != KEYD_OK)
        failures++;
}

static int check_link(void)
{
    unsigned char hello[2 * KEYD_LINK_HELLO_LEN], pa[32], pb[32];
    unsigned char frame[128], plain[64];
    size_t frame_len = 0, plain_len = 0;
    const char msg[] = "depot 0412 heartbeat";
    int rc = KEYD_ERR_LIB;

    struct keyd_link_session *a = keyd_link_session_new(1);
    struct keyd_link_session *b = keyd_link_session_new(0);
    if (a == NULL || b == NULL)
        goto out;
    randombytes_buf(hello, sizeof hello);
    if ((rc = keyd_link_session_public(a, pa, sizeof pa)) != KEYD_OK || (rc = keyd_link_session_public(b, pb, sizeof pb)) != KEYD_OK)
        goto out;
    if ((rc = keyd_link_session_establish(a, pb, sizeof pb, hello, sizeof hello)) != KEYD_OK)
        goto out;
    if ((rc = keyd_link_session_establish(b, pa, sizeof pa, hello, sizeof hello)) != KEYD_OK)
        goto out;
    if ((rc = keyd_link_seal(a, (const unsigned char *)msg, sizeof msg, frame, sizeof frame, &frame_len)) != KEYD_OK)
        goto out;
    if ((rc = keyd_link_open(b, frame, frame_len, plain, sizeof plain, &plain_len)) != KEYD_OK)
        goto out;
    rc = plain_len == sizeof msg && memcmp(plain, msg, sizeof msg) == 0 ? KEYD_OK : KEYD_ERR_AUTH;
out:
    keyd_link_session_free(a);
    keyd_link_session_free(b);
    return rc;
}

/* Plays the gateway side of a rotation: a fresh gateway key, then the bridge side of the exchange. */
static int check_rekey(void)
{
    unsigned char hello[2 * KEYD_LINK_HELLO_LEN], peer[32], pub[2048], ct[2048];
    size_t pub_len = 0, ct_len = 0;
    EVP_PKEY *gw = NULL;
    int rc = KEYD_ERR_LIB;

    struct keyd_link_session *s = keyd_link_session_new(0);
    struct keyd_link_session *g = keyd_link_session_new(1);
    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_from_name(NULL, KEYD_DEPOT_KEM, NULL);
    if (s == NULL || g == NULL || gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0 || EVP_PKEY_generate(gctx, &gw) <= 0)
        goto out;
    if (EVP_PKEY_get_octet_string_param(gw, OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof pub, &pub_len) != 1)
        goto out;
    randombytes_buf(hello, sizeof hello);
    if (keyd_link_session_public(g, peer, sizeof peer) != KEYD_OK)
        goto out;
    if ((rc = keyd_link_session_establish(s, peer, sizeof peer, hello, sizeof hello)) != KEYD_OK)
        goto out;
    rc = keyd_rekey_gateway(s, pub, pub_len, ct, sizeof ct, &ct_len);
out:
    EVP_PKEY_free(gw);
    EVP_PKEY_CTX_free(gctx);
    keyd_link_session_free(s);
    keyd_link_session_free(g);
    return rc;
}

static int check_audit(const char *dir)
{
    unsigned char key[64], seg_key[KEYD_SEGMENT_KEY_LEN], sealed[512];
    size_t sealed_len = 0;
    randombytes_buf(key, sizeof key);
    randombytes_buf(seg_key, sizeof seg_key);
    int rc = keyd_audit_open(dir, key, sizeof key);
    if (rc == KEYD_OK)
        rc = keyd_audit_append("self-check", "start", "pid %ld", (long)getpid());
    if (rc == KEYD_OK)
        rc = keyd_audit_flush();
    if (rc == KEYD_OK) {
        char records[] = "1\tself-check\tstart\n";
        struct audit_segment seg = { .id = "self-check-0001", .data = (unsigned char *)records, .len = sizeof records - 1 };
        rc = keyd_segment_seal(&seg, seg_key, sealed, sizeof sealed, &sealed_len);
    }
    crypto_wipe(key, sizeof key);
    crypto_wipe(seg_key, sizeof seg_key);
    return rc;
}

/* Throwaway credentials: random hex of the requested length. */
static void scratch_secret(char *out, size_t n)
{
    unsigned char raw[32];
    randombytes_buf(raw, sizeof raw);
    crypto_hex_encode(out, n + 1, raw, n / 2);
    crypto_wipe(raw, sizeof raw);
}

static int check_console(const char *dir)
{
    char path[512], login[33], other[33], pin[9], opened[32];
    scratch_secret(login, 32);
    scratch_secret(other, 32);
    scratch_secret(pin, 8);

    snprintf(path, sizeof path, "%s/operators", dir);
    int rc = keyd_operator_set_password(path, "self.check", login);
    if (rc == KEYD_OK)
        rc = keyd_operator_login(path, "self.check", login);
    if (rc == KEYD_OK)
        rc = keyd_operator_login(path, "self.check", other) == KEYD_ERR_AUTH ? KEYD_OK : KEYD_ERR_AUTH;
    snprintf(path, sizeof path, "%s/pin.vault", dir);
    if (rc == KEYD_OK)
        rc = keyd_vault_store_pin(path, other, pin);
    if (rc == KEYD_OK)
        rc = keyd_vault_unlock_pin(path, other, opened, sizeof opened);
    if (rc == KEYD_OK)
        rc = strcmp(opened, pin) == 0 ? KEYD_OK : KEYD_ERR_AUTH;
    crypto_wipe(login, sizeof login);
    crypto_wipe(other, sizeof other);
    return rc;
}

static int check_enrolment(void)
{
    struct depot d = { .number = 412, .code = "D0412", .region = "north" };
    unsigned char master[32], key[32], tag[32];
    char token[512];
    const unsigned char ack[] = "D0412 GW-88213 4.2.0";

    randombytes_buf(master, sizeof master);
    randombytes_buf(key, sizeof key);
    int rc = keyd_depot_derive_keys(&d, master);
    if (rc == KEYD_OK)
        rc = keyd_enrol_token_issue(&d, key, sizeof key, time(NULL), token, sizeof token);
    if (rc == KEYD_OK)
        rc = keyd_enrol_ack(&d, ack, sizeof ack - 1, tag);
    if (rc == KEYD_OK)
        rc = keyd_enrol_ack_check(&d, ack, sizeof ack - 1, tag);
    crypto_wipe(master, sizeof master);
    crypto_wipe(key, sizeof key);
    return rc;
}

static int check_signing(const char *dir)
{
    unsigned char seed[32], sig[4096];
    size_t sig_len = 0;
    char header[200];
    struct keyd_buf pem = { 0 };
    struct receipt r = { .consignment = "TB-26-0004417", .depot = "D0412", .signed_by = "J. Okafor" };
    struct config_bundle b = { .depot = "D0412", .data = (unsigned char *)"dock 3 closed", .len = 13 };

    r.delivered_at = time(NULL);
    randombytes_buf(seed, sizeof seed);
    int rc = keyd_webhook_sign(seed, time(NULL), "{\"event\":\"delivered\"}", 21, header, sizeof header);
    if (rc == KEYD_OK)
        rc = keyd_receipt_key_rotate(NULL);
    if (rc == KEYD_OK)
        rc = keyd_receipt_sign(&r, sig, sizeof sig, &sig_len);
    if (rc == KEYD_OK)
        rc = keyd_bundle_content_id(&b);
    if (rc == KEYD_OK)
        rc = keyd_partner_key_create(dir, "self-check", &pem);
    if (rc == KEYD_OK)
        rc = keyd_tech_key_begin("TECH-0001", &pem);
    keyd_receipt_key_free();
    keyd_buf_free(&pem);
    crypto_wipe(seed, sizeof seed);
    return rc;
}

static int check_gatepass(const char *dir)
{
    char qr[4096];
    time_t now = time(NULL);
    struct gate_pass gp = { .plate = "TB12XKR", .depot = "D0412", .dock = 7, .not_before = now, .not_after = now + 3600 };
    int rc = keyd_gatepass_new_key(dir);
    if (rc == KEYD_OK)
        rc = keyd_gatepass_issue(&gp, dir, qr, sizeof qr);
    return rc;
}

static int check_vendor_links(void)
{
    const char sale[] = "PL004417|5100********2291|88213|D50:Diesel B7:41250:6188";
    unsigned char frame[1024], key[16], cmd[64], hpk[crypto_kx_PUBLICKEYBYTES], hsk[crypto_kx_SECRETKEYBYTES];
    unsigned char relay[256];
    size_t frame_len = 0, cmd_len = 0, relay_len = 0;
    char code[8];
    struct keyd_handheld h;

    int rc = keyd_fuelcard_encode_sale(sale, frame, sizeof frame, &frame_len);
    if (rc == KEYD_OK)
        rc = keyd_fuelcard_decode_reply(frame, frame_len, code, sizeof code);
    if (rc == KEYD_OK) {
        randombytes_buf(key, sizeof key);
        rc = keyd_barrier_command(key, "N-GATE2", 1, 4417, cmd, sizeof cmd, &cmd_len);
    }
    if (rc == KEYD_OK)
        rc = keyd_handheld_init();
    if (rc == KEYD_OK) {
        crypto_kx_keypair(hpk, hsk);
        rc = keyd_handheld_pair("CR-20931", hpk, &h);
    }
    if (rc == KEYD_OK)
        rc = keyd_handheld_relay(&h, (const unsigned char *)"hold parcel 7781", 16, relay, sizeof relay, &relay_len);
    crypto_wipe(key, sizeof key);
    crypto_wipe(hsk, sizeof hsk);
    return rc;
}

static int check_listener(void)
{
    SSL_CTX *ctx = keyd_tls_server_new(0);
    if (ctx == NULL)
        return KEYD_ERR_LIB;
    SSL_CTX_free(ctx);
    return KEYD_OK;
}

static void remove_tree(const char *dir)
{
    char cmd[600];
    snprintf(cmd, sizeof cmd, "rm -rf -- '%s'", dir);
    if (system(cmd) != 0)
        fprintf(stderr, "self-check: could not remove %s\n", dir);
}

int keyd_self_check(void)
{
    char dir[] = "/tmp/tbkeyd-check.XXXXXX";
    failures = 0;

    if (sodium_init() < 0 || mkdtemp(dir) == NULL) {
        puts("FAIL set-up");
        return 1;
    }
    report("random generator", keyd_rng_init());
    report("link algorithms", keyd_link_init());
    report("depot link session", check_link());
    report("gateway key rotation", check_rekey());
    report("audit chain and segments", check_audit(dir));
    report("operator console", check_console(dir));
    report("enrolment", check_enrolment());
    report("signing", check_signing(dir));
    report("gate passes", check_gatepass(dir));
    report("vendor, yard and courier links", check_vendor_links());
    report("listener profile", check_listener());
    report("firmware root", keyd_release_root_ready());
    report("export profiles", keyd_export_profile("auditor") != NULL ? KEYD_OK : KEYD_ERR_NOTFOUND);

    keyd_audit_close();
    keyd_link_shutdown();
    keyd_rng_free();
    remove_tree(dir);
    printf("self-check: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}
