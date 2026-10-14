/*
 * Request dispatch. Each verb names the role allowed to call it; the role comes from the prefix of
 * the client certificate's common name. Every state-changing verb writes an audit record.
 */
#include "api/handlers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "api/request.h"
#include "keyd/audit.h"
#include "keyd/crypto_api.h"
#include "keyd/export.h"
#include "keyd/paths.h"
#include "util/crypto_util.h"
#include "util/log.h"

#define HEX_ARG_MAX (64u << 10)

struct handler {
    const char *verb;
    enum keyd_role role;
    int (*fn)(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out);
};

enum keyd_role keyd_role_for_peer(const char *cn)
{
    if (strncmp(cn, "gw-", 3) == 0)
        return ROLE_GATEWAY;
    if (strncmp(cn, "svc-", 4) == 0)
        return ROLE_SERVICE;
    if (strncmp(cn, "ops-", 4) == 0)
        return ROLE_CONSOLE;
    if (strncmp(cn, "bo-", 3) == 0)
        return ROLE_BACK_OFFICE;
    return ROLE_NONE;
}

void keyd_session_end(struct keyd_session *s)
{
    keyd_link_session_free(s->link);
    s->link = NULL;
    crypto_wipe(&s->handheld, sizeof s->handheld);
    s->handheld_paired = 0;
}

/* ---- argument helpers */

static int hex_arg(const struct keyd_request *req, size_t i, struct keyd_buf *out)
{
    const char *a = keyd_request_arg(req, i);
    size_t n = 0;
    if (a == NULL || strlen(a) / 2 > HEX_ARG_MAX)
        return KEYD_ERR_ARGS;
    if (keyd_buf_reserve(out, strlen(a) / 2 + 1) != KEYD_OK)
        return KEYD_ERR_NOMEM;
    if (crypto_hex_decode(out->data, out->cap, a, &n) != 0)
        return KEYD_ERR_ARGS;
    out->len = n;
    return KEYD_OK;
}

static int text_arg(const struct keyd_request *req, size_t i, const char **out)
{
    *out = keyd_request_arg(req, i);
    return *out != NULL ? KEYD_OK : KEYD_ERR_ARGS;
}

static int number_arg(const struct keyd_request *req, size_t i, long long *out)
{
    const char *a = keyd_request_arg(req, i);
    char *end = NULL;
    if (a == NULL)
        return KEYD_ERR_ARGS;
    *out = strtoll(a, &end, 10);
    return *end == '\0' ? KEYD_OK : KEYD_ERR_ARGS;
}

static int put_hex(struct keyd_buf *out, const unsigned char *p, size_t n)
{
    int rc = keyd_buf_reserve(out, 2 * n + 1);
    if (rc != KEYD_OK)
        return rc;
    crypto_hex_encode((char *)out->data + out->len, out->cap - out->len, p, n);
    out->len += 2 * n;
    return KEYD_OK;
}

static int load_secret(const char *name, unsigned char *out, size_t len)
{
    char path[512];
    struct keyd_buf b = { 0 };
    snprintf(path, sizeof path, "%s/%s", KEYD_SECRETS_DIR, name);
    int rc = keyd_read_file(path, 4096, &b);
    if (rc == KEYD_OK && b.len != len)
        rc = KEYD_ERR_ARGS;
    if (rc == KEYD_OK)
        memcpy(out, b.data, len);
    else
        log_err("secrets: %s unusable: %s", name, keyd_status_str(rc));
    keyd_buf_free(&b);
    return rc;
}

static int depot_from_args(const struct keyd_request *req, size_t first, struct depot *d)
{
    const char *code, *region;
    long long number;
    memset(d, 0, sizeof *d);
    if (text_arg(req, first, &code) != KEYD_OK || number_arg(req, first + 1, &number) != KEYD_OK
        || text_arg(req, first + 2, &region) != KEYD_OK || number <= 0)
        return KEYD_ERR_ARGS;
    snprintf(d->code, sizeof d->code, "%s", code);
    snprintf(d->region, sizeof d->region, "%s", region);
    d->number = (uint64_t)number;
    return KEYD_OK;
}

/* ---- depot link */

static int h_link_hello(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    struct keyd_buf peer = { 0 }, hello = { 0 };
    unsigned char ours[32];
    int rc = hex_arg(req, 0, &peer);
    if (rc == KEYD_OK)
        rc = hex_arg(req, 1, &hello);
    if (rc == KEYD_OK) {
        keyd_link_session_free(s->link);
        s->link = keyd_link_session_new(0);
        rc = s->link ? KEYD_OK : KEYD_ERR_LIB;
    }
    if (rc == KEYD_OK)
        rc = keyd_link_session_establish(s->link, peer.data, peer.len, hello.data, hello.len);
    if (rc == KEYD_OK)
        rc = keyd_link_session_public(s->link, ours, sizeof ours);
    if (rc == KEYD_OK)
        rc = put_hex(out, ours, sizeof ours);
    keyd_buf_free(&peer);
    keyd_buf_free(&hello);
    return rc;
}

static int h_link_rekey(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    struct keyd_buf pub = { 0 };
    unsigned char ct[2048];
    size_t ct_len = 0;
    if (s->link == NULL)
        return KEYD_ERR_POLICY;
    int rc = hex_arg(req, 0, &pub);
    if (rc == KEYD_OK)
        rc = keyd_rekey_gateway(s->link, pub.data, pub.len, ct, sizeof ct, &ct_len);
    if (rc == KEYD_OK)
        rc = put_hex(out, ct, ct_len);
    keyd_buf_free(&pub);
    if (rc == KEYD_OK)
        keyd_audit_append(s->peer, "link-rekey", "ok");
    return rc;
}

/* ---- partition operations */

static int h_wrap_key(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    const char *label;
    unsigned char wrapped[KEYD_LINK_KEY_LEN * 2 + 16];
    size_t len = sizeof wrapped;
    int rc = text_arg(req, 0, &label);
    if (rc == KEYD_OK)
        rc = keyd_p11_wrap_data_key(s->p11, label, wrapped, &len);
    if (rc == KEYD_OK)
        rc = put_hex(out, wrapped, len);
    keyd_audit_append(s->peer, "wrap-key", "%s %s", label ? label : "-", keyd_status_str(rc));
    return rc;
}

static int h_seal_blob(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    const char *label;
    struct keyd_buf aad = { 0 }, data = { 0 };
    unsigned char iv[12];
    unsigned char *sealed = NULL;
    size_t sealed_len = 0;

    int rc = text_arg(req, 0, &label);
    if (rc == KEYD_OK)
        rc = hex_arg(req, 1, &aad);
    if (rc == KEYD_OK)
        rc = hex_arg(req, 2, &data);
    if (rc == KEYD_OK)
        rc = keyd_rng_bytes(iv, sizeof iv);
    if (rc == KEYD_OK) {
        sealed_len = data.len + 16;
        sealed = malloc(sealed_len);
        rc = sealed ? KEYD_OK : KEYD_ERR_NOMEM;
    }
    if (rc == KEYD_OK)
        rc = keyd_p11_seal(s->p11, label, iv, sizeof iv, aad.data, aad.len, data.data, data.len, sealed, &sealed_len);
    if (rc == KEYD_OK)
        rc = put_hex(out, iv, sizeof iv);
    if (rc == KEYD_OK)
        rc = put_hex(out, sealed, sealed_len);
    free(sealed);
    keyd_buf_free(&aad);
    keyd_buf_free(&data);
    return rc;
}

static int h_sign_settlement(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    struct keyd_buf file = { 0 };
    unsigned char sig[512];
    size_t sig_len = sizeof sig;
    int rc = hex_arg(req, 0, &file);
    if (rc == KEYD_OK)
        rc = keyd_p11_sign_settlement(s->p11, file.data, file.len, sig, &sig_len);
    if (rc == KEYD_OK)
        rc = put_hex(out, sig, sig_len);
    keyd_audit_append(s->peer, "sign-settlement", "%zu bytes %s", file.len, keyd_status_str(rc));
    keyd_buf_free(&file);
    return rc;
}

/* ---- archive keys */

static int h_escrow_key(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    const char *archive_id;
    struct keyd_buf key = { 0 };
    int rc = text_arg(req, 0, &archive_id);
    if (rc == KEYD_OK)
        rc = hex_arg(req, 1, &key);
    if (rc == KEYD_OK && key.len != 32)
        rc = KEYD_ERR_ARGS;
    if (rc == KEYD_OK)
        rc = keyd_escrow_archive_key(key.data, archive_id, out);
    keyd_audit_append(s->peer, "escrow-key", "%s %s", archive_id ? archive_id : "-", keyd_status_str(rc));
    keyd_buf_free(&key);
    return rc;
}

static int h_unwrap_archive(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    struct keyd_buf encap = { 0 };
    unsigned char key[32];
    int rc = hex_arg(req, 0, &encap);
    if (rc == KEYD_OK)
        rc = keyd_archive_unwrap(encap.data, encap.len, key);
    if (rc == KEYD_OK)
        rc = put_hex(out, key, sizeof key);
    crypto_wipe(key, sizeof key);
    keyd_audit_append(s->peer, "unwrap-archive", "%s", keyd_status_str(rc));
    keyd_buf_free(&encap);
    return rc;
}

/* ---- enrolment */

static int h_enrol_token(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    struct depot d;
    unsigned char key[32];
    char token[512];
    int rc = depot_from_args(req, 0, &d);
    if (rc == KEYD_OK)
        rc = load_secret("enrol-token.key", key, sizeof key);
    if (rc == KEYD_OK)
        rc = keyd_enrol_token_issue(&d, key, sizeof key, time(NULL), token, sizeof token);
    if (rc == KEYD_OK)
        rc = keyd_buf_printf(out, "%s", token);
    crypto_wipe(key, sizeof key);
    keyd_audit_append(s->peer, "enrol-token", "depot %s %s", d.code, keyd_status_str(rc));
    return rc;
}

static int h_enrol_ack(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    struct depot d;
    struct keyd_buf ack = { 0 };
    unsigned char master[32], tag[32];
    char name[48];
    int rc = depot_from_args(req, 0, &d);
    if (rc == KEYD_OK)
        rc = hex_arg(req, 3, &ack);
    if (rc == KEYD_OK) {
        snprintf(name, sizeof name, "region-%s.key", d.region);
        rc = load_secret(name, master, sizeof master);
    }
    if (rc == KEYD_OK)
        rc = keyd_depot_derive_keys(&d, master);
    if (rc == KEYD_OK)
        rc = keyd_enrol_ack(&d, ack.data, ack.len, tag);
    if (rc == KEYD_OK)
        rc = put_hex(out, tag, sizeof tag);
    crypto_wipe(master, sizeof master);
    crypto_wipe(&d, sizeof d);
    keyd_buf_free(&ack);
    (void)s;
    return rc;
}

/* ---- signing */

static int h_sign_bundle(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    const char *depot;
    struct keyd_buf data = { 0 };
    unsigned char sk[64];
    struct config_bundle b;
    memset(&b, 0, sizeof b);
    int rc = text_arg(req, 0, &depot);
    if (rc == KEYD_OK)
        rc = hex_arg(req, 1, &data);
    if (rc == KEYD_OK)
        rc = load_secret("bundle-signing.sk", sk, sizeof sk);
    if (rc == KEYD_OK) {
        snprintf(b.depot, sizeof b.depot, "%s", depot);
        b.data = data.data;
        b.len = data.len;
        rc = keyd_bundle_sign(&b, sk);
    }
    if (rc == KEYD_OK)
        rc = put_hex(out, b.content_id, sizeof b.content_id);
    if (rc == KEYD_OK)
        rc = keyd_buf_append(out, " ", 1);
    if (rc == KEYD_OK)
        rc = put_hex(out, b.sig, sizeof b.sig);
    crypto_wipe(sk, sizeof sk);
    keyd_buf_free(&data);
    keyd_audit_append(s->peer, "sign-bundle", "%s", keyd_status_str(rc));
    return rc;
}

static int h_sign_receipt(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    struct receipt r;
    const char *consignment, *depot, *signed_by;
    long long at;
    unsigned char sig[4096];
    size_t sig_len = 0;
    memset(&r, 0, sizeof r);
    int rc = text_arg(req, 0, &consignment);
    if (rc == KEYD_OK)
        rc = text_arg(req, 1, &depot);
    if (rc == KEYD_OK)
        rc = text_arg(req, 2, &signed_by);
    if (rc == KEYD_OK)
        rc = number_arg(req, 3, &at);
    if (rc == KEYD_OK) {
        snprintf(r.consignment, sizeof r.consignment, "%s", consignment);
        snprintf(r.depot, sizeof r.depot, "%s", depot);
        snprintf(r.signed_by, sizeof r.signed_by, "%s", signed_by);
        r.delivered_at = (time_t)at;
        rc = keyd_receipt_sign(&r, sig, sizeof sig, &sig_len);
    }
    if (rc == KEYD_OK)
        rc = put_hex(out, sig, sig_len);
    (void)s;
    return rc;
}

static int h_sign_webhook(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    const char *partner;
    long long ts;
    struct keyd_buf body = { 0 };
    unsigned char seed[32];
    char name[64], header[200];
    int rc = text_arg(req, 0, &partner);
    if (rc == KEYD_OK)
        rc = number_arg(req, 1, &ts);
    if (rc == KEYD_OK)
        rc = hex_arg(req, 2, &body);
    if (rc == KEYD_OK) {
        snprintf(name, sizeof name, "webhook-%s.seed", partner);
        rc = load_secret(name, seed, sizeof seed);
    }
    if (rc == KEYD_OK)
        rc = keyd_webhook_sign(seed, (time_t)ts, (const char *)body.data, body.len, header, sizeof header);
    if (rc == KEYD_OK)
        rc = keyd_buf_printf(out, "%s", header);
    crypto_wipe(seed, sizeof seed);
    keyd_buf_free(&body);
    (void)s;
    return rc;
}

static int h_gate_pass(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    struct gate_pass gp;
    const char *plate, *depot;
    long long dock, nbf, exp;
    char qr[4096];
    memset(&gp, 0, sizeof gp);
    int rc = text_arg(req, 0, &plate);
    if (rc == KEYD_OK)
        rc = text_arg(req, 1, &depot);
    if (rc == KEYD_OK)
        rc = number_arg(req, 2, &dock);
    if (rc == KEYD_OK)
        rc = number_arg(req, 3, &nbf);
    if (rc == KEYD_OK)
        rc = number_arg(req, 4, &exp);
    if (rc == KEYD_OK && (dock < 0 || dock > 999))
        rc = KEYD_ERR_ARGS;
    if (rc == KEYD_OK) {
        snprintf(gp.plate, sizeof gp.plate, "%s", plate);
        snprintf(gp.depot, sizeof gp.depot, "%s", depot);
        gp.dock = (uint16_t)dock;
        gp.not_before = (time_t)nbf;
        gp.not_after = (time_t)exp;
        rc = keyd_gatepass_issue(&gp, KEYD_SECRETS_DIR, qr, sizeof qr);
    }
    if (rc == KEYD_OK)
        rc = keyd_buf_printf(out, "%s", qr);
    keyd_audit_append(s->peer, "gate-pass", "%s %s", gp.plate, keyd_status_str(rc));
    return rc;
}

/* ---- console */

static int h_check_release(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    const char *version;
    struct release rel;
    int rc = text_arg(req, 0, &version);
    if (rc == KEYD_OK)
        rc = keyd_release_load(s->cfg->release_dir, version, &rel);
    if (rc == KEYD_OK) {
        rc = keyd_release_check(&rel);
        keyd_release_free(&rel);
    }
    keyd_audit_append(s->peer, "check-release", "%s %s", version ? version : "-", keyd_status_str(rc));
    if (rc == KEYD_OK)
        rc = keyd_buf_printf(out, "staged");
    return rc;
}

static int h_partner_key(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    const char *partner;
    int rc = text_arg(req, 0, &partner);
    if (rc == KEYD_OK)
        rc = keyd_partner_key_create(KEYD_PARTNER_DIR, partner, out);
    keyd_audit_append(s->peer, "partner-key", "%s %s", partner ? partner : "-", keyd_status_str(rc));
    return rc;
}

static int h_tech_key(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    const char *tech;
    int rc = text_arg(req, 0, &tech);
    keyd_tech_expire(time(NULL));
    if (rc == KEYD_OK)
        rc = keyd_tech_key_begin(tech, out);
    keyd_audit_append(s->peer, "tech-key", "%s %s", tech ? tech : "-", keyd_status_str(rc));
    return rc;
}

static int h_tech_bundle(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    const char *tech, *pass;
    struct keyd_buf cert = { 0 }, bundle = { 0 };
    int rc = text_arg(req, 0, &tech);
    if (rc == KEYD_OK)
        rc = hex_arg(req, 1, &cert);
    if (rc == KEYD_OK)
        rc = text_arg(req, 2, &pass);
    if (rc == KEYD_OK)
        rc = keyd_buf_append(&cert, "", 1);
    if (rc == KEYD_OK)
        rc = keyd_tech_bundle_finish(tech, (const char *)cert.data, pass, &bundle);
    if (rc == KEYD_OK)
        rc = put_hex(out, bundle.data, bundle.len);
    keyd_audit_append(s->peer, "tech-bundle", "%s %s", tech ? tech : "-", keyd_status_str(rc));
    keyd_buf_free(&cert);
    keyd_buf_free(&bundle);
    return rc;
}

static int h_audit_export(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    long long from, to;
    const char *pass;
    struct keyd_buf file = { 0 };
    int rc = number_arg(req, 0, &from);
    if (rc == KEYD_OK)
        rc = number_arg(req, 1, &to);
    if (rc == KEYD_OK)
        rc = text_arg(req, 2, &pass);
    if (rc == KEYD_OK)
        rc = keyd_export_report(&AUDITOR_PROFILE, pass, (time_t)from, (time_t)to, &file);
    if (rc == KEYD_OK)
        rc = put_hex(out, file.data, file.len);
    keyd_audit_append(s->peer, "audit-export", "%lld..%lld %s", from, to, keyd_status_str(rc));
    keyd_buf_free(&file);
    return rc;
}

static int h_appliance_import(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    struct keyd_buf file = { 0 };
    const char *pass;
    int rc = hex_arg(req, 0, &file);
    if (rc == KEYD_OK)
        rc = text_arg(req, 1, &pass);
    if (rc == KEYD_OK)
        rc = keyd_appliance_import(file.data, file.len, pass, out);
    keyd_audit_append(s->peer, "appliance-import", "%s", keyd_status_str(rc));
    keyd_buf_free(&file);
    return rc;
}

/* ---- vendors, yard, couriers */

static int h_fuel_sale(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    struct keyd_buf line = { 0 };
    unsigned char frame[1024];
    size_t frame_len = 0;
    int rc = hex_arg(req, 0, &line);
    if (rc == KEYD_OK)
        rc = keyd_buf_append(&line, "", 1);
    if (rc == KEYD_OK)
        rc = keyd_fuelcard_encode_sale((const char *)line.data, frame, sizeof frame, &frame_len);
    if (rc == KEYD_OK)
        rc = put_hex(out, frame, frame_len);
    keyd_buf_free(&line);
    (void)s;
    return rc;
}

static int h_fuel_reply(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    struct keyd_buf frame = { 0 };
    char code[8];
    int rc = hex_arg(req, 0, &frame);
    if (rc == KEYD_OK)
        rc = keyd_fuelcard_decode_reply(frame.data, frame.len, code, sizeof code);
    if (rc == KEYD_OK)
        rc = keyd_buf_printf(out, "%s", code);
    keyd_buf_free(&frame);
    (void)s;
    return rc;
}

static int h_barrier(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    const char *gate;
    long long action, counter;
    unsigned char key[16], cmd[64];
    size_t cmd_len = 0;
    char name[48];
    int rc = text_arg(req, 0, &gate);
    if (rc == KEYD_OK)
        rc = number_arg(req, 1, &action);
    if (rc == KEYD_OK)
        rc = number_arg(req, 2, &counter);
    if (rc == KEYD_OK && (counter < 0 || counter > UINT32_MAX))
        rc = KEYD_ERR_ARGS;
    if (rc == KEYD_OK) {
        snprintf(name, sizeof name, "barrier-%s.key", gate);
        rc = load_secret(name, key, sizeof key);
    }
    if (rc == KEYD_OK)
        rc = keyd_barrier_command(key, gate, (int)action, (uint32_t)counter, cmd, sizeof cmd, &cmd_len);
    if (rc == KEYD_OK)
        rc = put_hex(out, cmd, cmd_len);
    crypto_wipe(key, sizeof key);
    keyd_audit_append(s->peer, "barrier", "%s %lld %s", gate ? gate : "-", action, keyd_status_str(rc));
    return rc;
}

static int h_handheld_pair(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    const char *courier;
    struct keyd_buf pub = { 0 };
    unsigned char ours[KEYD_HANDHELD_PUB_LEN];
    int rc = text_arg(req, 0, &courier);
    if (rc == KEYD_OK)
        rc = hex_arg(req, 1, &pub);
    if (rc == KEYD_OK && pub.len != KEYD_HANDHELD_PUB_LEN)
        rc = KEYD_ERR_ARGS;
    if (rc == KEYD_OK)
        rc = keyd_handheld_pair(courier, pub.data, &s->handheld);
    if (rc == KEYD_OK)
        rc = keyd_handheld_server_public(ours);
    if (rc == KEYD_OK) {
        s->handheld_paired = 1;
        rc = put_hex(out, ours, sizeof ours);
    }
    keyd_buf_free(&pub);
    return rc;
}

static int h_handheld_relay(struct keyd_session *s, const struct keyd_request *req, struct keyd_buf *out)
{
    struct keyd_buf msg = { 0 };
    unsigned char frame[4096 + 32];
    size_t frame_len = 0;
    if (!s->handheld_paired)
        return KEYD_ERR_POLICY;
    int rc = hex_arg(req, 0, &msg);
    if (rc == KEYD_OK)
        rc = keyd_handheld_relay(&s->handheld, msg.data, msg.len, frame, sizeof frame, &frame_len);
    if (rc == KEYD_OK)
        rc = put_hex(out, frame, frame_len);
    keyd_buf_free(&msg);
    return rc;
}

static const struct handler HANDLERS[] = {
    { "link-hello", ROLE_GATEWAY, h_link_hello },
    { "link-rekey", ROLE_GATEWAY, h_link_rekey },
    { "enrol-ack", ROLE_GATEWAY, h_enrol_ack },
    { "wrap-key", ROLE_SERVICE, h_wrap_key },
    { "seal-blob", ROLE_SERVICE, h_seal_blob },
    { "sign-settlement", ROLE_SERVICE, h_sign_settlement },
    { "escrow-key", ROLE_SERVICE, h_escrow_key },
    { "sign-bundle", ROLE_SERVICE, h_sign_bundle },
    { "sign-receipt", ROLE_SERVICE, h_sign_receipt },
    { "sign-webhook", ROLE_SERVICE, h_sign_webhook },
    { "gate-pass", ROLE_SERVICE, h_gate_pass },
    { "barrier", ROLE_SERVICE, h_barrier },
    { "handheld-pair", ROLE_SERVICE, h_handheld_pair },
    { "handheld-relay", ROLE_SERVICE, h_handheld_relay },
    { "fuel-sale", ROLE_BACK_OFFICE, h_fuel_sale },
    { "fuel-reply", ROLE_BACK_OFFICE, h_fuel_reply },
    { "unwrap-archive", ROLE_CONSOLE, h_unwrap_archive },
    { "enrol-token", ROLE_CONSOLE, h_enrol_token },
    { "check-release", ROLE_CONSOLE, h_check_release },
    { "partner-key", ROLE_CONSOLE, h_partner_key },
    { "tech-key", ROLE_CONSOLE, h_tech_key },
    { "tech-bundle", ROLE_CONSOLE, h_tech_bundle },
    { "audit-export", ROLE_CONSOLE, h_audit_export },
    { "appliance-import", ROLE_CONSOLE, h_appliance_import },
};

int keyd_handle_line(struct keyd_session *s, char *line, char *reply, size_t reply_cap)
{
    struct keyd_request req;
    struct keyd_buf out = { 0 };
    int rc = keyd_request_parse(line, &req);
    if (rc != KEYD_OK)
        return keyd_reply_err(reply, reply_cap, rc, "malformed request");

    const struct handler *h = NULL;
    for (size_t i = 0; i < sizeof HANDLERS / sizeof HANDLERS[0]; i++) {
        if (strcmp(HANDLERS[i].verb, req.verb) == 0) {
            h = &HANDLERS[i];
            break;
        }
    }
    if (h == NULL)
        return keyd_reply_err(reply, reply_cap, KEYD_ERR_ARGS, "unknown verb");
    if (h->role != s->role) {
        log_warn("api: %s may not call %s", s->peer, req.verb);
        return keyd_reply_err(reply, reply_cap, KEYD_ERR_AUTH, NULL);
    }

    rc = h->fn(s, &req, &out);
    int n;
    if (rc == KEYD_OK) {
        if (keyd_buf_append(&out, "", 1) != KEYD_OK)
            n = keyd_reply_err(reply, reply_cap, KEYD_ERR_NOMEM, NULL);
        else
            n = keyd_reply_ok(reply, reply_cap, out.len > 1 ? (const char *)out.data : NULL);
    } else {
        log_info("api: %s %s -> %s", s->peer, req.verb, keyd_status_str(rc));
        n = keyd_reply_err(reply, reply_cap, rc, NULL);
    }
    keyd_buf_free(&out);
    return n;
}
