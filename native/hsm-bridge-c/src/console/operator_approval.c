/*
 * Quorum approval. Destructive console operations (deleting a partition object, rotating the KEK,
 * re-initialising the vault) need two operators. Each operator plugs in their PIV card; the card
 * signs the approval challenge with its digital-signature key (PIV slot 9C), and the signature goes
 * into the audit chain next to the operation. Auditors check the signatures against the operators'
 * card certificates.
 */
#include <p11-kit/p11-kit.h>
#include <p11-kit/pkcs11.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keyd/audit.h"
#include "keyd/crypto_api.h"
#include "keyd/keyd.h"
#include "util/crypto_util.h"
#include "util/log.h"

/* OpenSC exposes PIV slot 9C with CKA_ID 02. */
static const CK_BYTE PIV_SIGNATURE_KEY_ID[] = { 0x02 };

struct card {
    CK_FUNCTION_LIST_PTR fn;
    CK_SESSION_HANDLE session;
    int initialised;
};

static void card_close(struct card *c)
{
    if (c->fn == NULL)
        return;
    if (c->session != CK_INVALID_HANDLE) {
        c->fn->C_Logout(c->session);
        c->fn->C_CloseSession(c->session);
    }
    if (c->initialised)
        p11_kit_module_finalize(c->fn);
    p11_kit_module_release(c->fn);
    memset(c, 0, sizeof *c);
}

static int card_open(struct card *c, const char *module_path, const char *token_label)
{
    memset(c, 0, sizeof *c);
    c->fn = p11_kit_module_load(module_path, 0);
    if (c->fn == NULL) {
        log_err("approval: cannot load %s", module_path);
        return KEYD_ERR_TOKEN;
    }
    if (p11_kit_module_initialize(c->fn) != CKR_OK) {
        card_close(c);
        return KEYD_ERR_TOKEN;
    }
    c->initialised = 1;

    CK_SLOT_ID slots[8];
    CK_ULONG count = 8;
    if (c->fn->C_GetSlotList(CK_TRUE, slots, &count) != CKR_OK || count == 0) {
        log_warn("approval: no card inserted");
        card_close(c);
        return KEYD_ERR_NOTFOUND;
    }
    size_t want = strlen(token_label);
    for (CK_ULONG i = 0; i < count; i++) {
        CK_TOKEN_INFO info;
        if (c->fn->C_GetTokenInfo(slots[i], &info) != CKR_OK)
            continue;
        if (want <= sizeof info.label && memcmp(info.label, token_label, want) == 0) {
            if (c->fn->C_OpenSession(slots[i], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &c->session) == CKR_OK)
                return KEYD_OK;
        }
    }
    log_warn("approval: no card labelled '%s'", token_label);
    card_close(c);
    return KEYD_ERR_NOTFOUND;
}

static int find_signature_key(struct card *c, CK_OBJECT_HANDLE *key)
{
    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_KEY_TYPE type = CKK_EC;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls, sizeof cls },
        { CKA_KEY_TYPE, &type, sizeof type },
        { CKA_ID, (CK_VOID_PTR)PIV_SIGNATURE_KEY_ID, sizeof PIV_SIGNATURE_KEY_ID },
    };
    CK_ULONG found = 0;
    CK_RV rv = c->fn->C_FindObjectsInit(c->session, tmpl, 3);
    if (rv == CKR_OK)
        rv = c->fn->C_FindObjects(c->session, key, 1, &found);
    c->fn->C_FindObjectsFinal(c->session);
    return rv == CKR_OK && found == 1 ? KEYD_OK : KEYD_ERR_NOTFOUND;
}

int keyd_approval_sign(const char *module_path, const char *token_label, const char *pin,
                       const unsigned char *challenge, size_t challenge_len, unsigned char *sig, size_t *sig_len)
{
    struct card c;
    int rc = card_open(&c, module_path, token_label);
    if (rc != KEYD_OK)
        return rc;

    CK_RV rv = c.fn->C_Login(c.session, CKU_USER, (CK_UTF8CHAR_PTR)pin, strlen(pin));
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
        rc = rv == CKR_PIN_INCORRECT ? KEYD_ERR_AUTH : KEYD_ERR_TOKEN;
        goto out;
    }

    CK_OBJECT_HANDLE key;
    if ((rc = find_signature_key(&c, &key)) != KEYD_OK)
        goto out;

    CK_MECHANISM approve = { CKM_ECDSA_SHA256, NULL_PTR, 0 };
    if (c.fn->C_SignInit(c.session, &approve, key) != CKR_OK) {
        rc = KEYD_ERR_TOKEN;
        goto out;
    }
    /* The 9C key asks for the PIN again for every signature. */
    rv = c.fn->C_Login(c.session, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR_PTR)pin, strlen(pin));
    if (rv != CKR_OK && rv != CKR_OPERATION_NOT_INITIALIZED) {
        rc = KEYD_ERR_AUTH;
        goto out;
    }
    CK_ULONG len = (CK_ULONG)*sig_len;
    if (c.fn->C_Sign(c.session, (CK_BYTE_PTR)challenge, challenge_len, sig, &len) != CKR_OK) {
        rc = KEYD_ERR_TOKEN;
        goto out;
    }
    *sig_len = len;
    rc = KEYD_OK;

out:
    card_close(&c);
    return rc;
}

/* Builds the challenge an operator approves: operation, request id and a server random. */
int keyd_approval_challenge(const char *operation, const char *request_id, unsigned char *out, size_t out_cap,
                            size_t *out_len)
{
    unsigned char rnd[16];
    int n = snprintf((char *)out, out_cap, "tbkeyd-approval\n%s\n%s\n", operation, request_id);
    if (n < 0 || (size_t)n + sizeof rnd > out_cap)
        return KEYD_ERR_ARGS;
    if (keyd_rng_bytes(rnd, sizeof rnd) != KEYD_OK)
        return KEYD_ERR_LIB;
    memcpy(out + n, rnd, sizeof rnd);
    *out_len = (size_t)n + sizeof rnd;
    return KEYD_OK;
}

/* Records one approval in the audit chain; the quorum check counts distinct operators. */
int keyd_approval_record(const char *operator_name, const char *operation, const unsigned char *sig, size_t sig_len)
{
    char hex[2 * 160 + 1];
    if (sig_len > 160 || crypto_hex_encode(hex, sizeof hex, sig, sig_len) == 0)
        return KEYD_ERR_ARGS;
    return keyd_audit_append(operator_name, "approval", "%s sig=%s", operation, hex);
}
