/*
 * Loading the vendor module, finding our partition by token label, and logging in. The module and
 * the label come from keyd.conf; the user PIN comes from the console vault at start-up.
 */
#include "keyd/hsm.h"

#include <p11-kit/p11-kit.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keyd/keyd.h"
#include "util/hash_table.h"
#include "util/log.h"

/* Token labels are 32 bytes, blank padded, not terminated. */
static int label_matches(const CK_UTF8CHAR label[32], const char *want)
{
    size_t n = strlen(want);
    if (n > 32 || memcmp(label, want, n) != 0)
        return 0;
    for (size_t i = n; i < 32; i++) {
        if (label[i] != ' ')
            return 0;
    }
    return 1;
}

static int find_slot(struct keyd_p11 *p, const char *slot_label)
{
    CK_ULONG count = 0;
    CK_RV rv = p->fn->C_GetSlotList(CK_TRUE, NULL_PTR, &count);
    if (rv != CKR_OK || count == 0) {
        log_err("token: no slots with a token present (rv=0x%lx)", (unsigned long)rv);
        return KEYD_ERR_TOKEN;
    }
    CK_SLOT_ID *slots = calloc(count, sizeof *slots);
    if (slots == NULL)
        return KEYD_ERR_NOMEM;

    int rc = KEYD_ERR_NOTFOUND;
    rv = p->fn->C_GetSlotList(CK_TRUE, slots, &count);
    for (CK_ULONG i = 0; rv == CKR_OK && i < count; i++) {
        CK_TOKEN_INFO info;
        if (p->fn->C_GetTokenInfo(slots[i], &info) != CKR_OK)
            continue;
        if (label_matches(info.label, slot_label)) {
            p->slot = slots[i];
            rc = KEYD_OK;
            break;
        }
    }
    free(slots);
    if (rc != KEYD_OK)
        log_err("token: no token labelled '%s'", slot_label);
    return rc;
}

int keyd_p11_open(struct keyd_p11 *p, const char *module_path, const char *slot_label)
{
    memset(p, 0, sizeof *p);
    p->fn = p11_kit_module_load(module_path, 0);
    if (p->fn == NULL) {
        log_err("token: cannot load module %s: %s", module_path, p11_kit_message());
        return KEYD_ERR_TOKEN;
    }
    CK_RV rv = p11_kit_module_initialize(p->fn);
    if (rv != CKR_OK) {
        log_err("token: module initialisation failed (rv=0x%lx)", (unsigned long)rv);
        p11_kit_module_release(p->fn);
        p->fn = NULL;
        return KEYD_ERR_TOKEN;
    }
    p->initialised = 1;

    int rc = find_slot(p, slot_label);
    if (rc != KEYD_OK) {
        keyd_p11_close(p);
        return rc;
    }
    rv = p->fn->C_OpenSession(p->slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &p->session);
    if (rv != CKR_OK) {
        log_err("token: cannot open a session on '%s' (rv=0x%lx)", slot_label, (unsigned long)rv);
        keyd_p11_close(p);
        return KEYD_ERR_TOKEN;
    }
    p->handles = calloc(1, sizeof *p->handles);
    if (p->handles == NULL || keyd_table_init(p->handles, 32) != KEYD_OK) {
        keyd_p11_close(p);
        return KEYD_ERR_NOMEM;
    }
    log_info("token: session open on '%s'", slot_label);
    return KEYD_OK;
}

int keyd_p11_login(struct keyd_p11 *p, const char *pin, size_t pin_len)
{
    CK_RV rv = p->fn->C_Login(p->session, CKU_USER, (CK_UTF8CHAR_PTR)pin, pin_len);
    if (rv == CKR_USER_ALREADY_LOGGED_IN)
        rv = CKR_OK;
    if (rv != CKR_OK) {
        log_err("token: login refused (rv=0x%lx)", (unsigned long)rv);
        return rv == CKR_PIN_INCORRECT ? KEYD_ERR_AUTH : KEYD_ERR_TOKEN;
    }
    p->logged_in = 1;
    return KEYD_OK;
}

void keyd_p11_close(struct keyd_p11 *p)
{
    if (p->fn == NULL)
        return;
    if (p->logged_in)
        p->fn->C_Logout(p->session);
    if (p->session != CK_INVALID_HANDLE)
        p->fn->C_CloseSession(p->session);
    if (p->initialised)
        p11_kit_module_finalize(p->fn);
    p11_kit_module_release(p->fn);
    if (p->handles != NULL) {
        keyd_table_free(p->handles, NULL);
        free(p->handles);
    }
    memset(p, 0, sizeof *p);
}

int keyd_p11_find(struct keyd_p11 *p, CK_OBJECT_CLASS cls, const char *label, CK_OBJECT_HANDLE *out)
{
    char cache_key[96];
    snprintf(cache_key, sizeof cache_key, "%lu/%s", (unsigned long)cls, label);
    void *cached = keyd_table_get(p->handles, cache_key);
    if (cached != NULL) {
        *out = (CK_OBJECT_HANDLE)((uintptr_t)cached - 1);
        return KEYD_OK;
    }

    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls, sizeof cls },
        { CKA_LABEL, (CK_VOID_PTR)label, strlen(label) },
    };
    CK_ULONG found = 0;
    CK_RV rv = p->fn->C_FindObjectsInit(p->session, tmpl, 2);
    if (rv == CKR_OK)
        rv = p->fn->C_FindObjects(p->session, out, 1, &found);
    p->fn->C_FindObjectsFinal(p->session);
    if (rv != CKR_OK)
        return KEYD_ERR_TOKEN;
    if (found == 0)
        return KEYD_ERR_NOTFOUND;
    keyd_table_put(p->handles, cache_key, (void *)((uintptr_t)*out + 1));
    return KEYD_OK;
}
