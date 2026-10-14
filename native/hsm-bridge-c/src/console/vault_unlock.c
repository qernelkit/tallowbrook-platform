/*
 * The console vault holds the HSM user PIN, sealed under a key derived from the vault passphrase
 * that two operators know half of each. tbkeyd reads it once at start-up.
 *
 * File layout: "TBV1" | salt | nonce | sealed PIN.
 */
#include <sodium.h>
#include <string.h>

#include "keyd/crypto_api.h"
#include "keyd/keyd.h"
#include "util/log.h"

#define VAULT_MAGIC "TBV1"
#define VAULT_PIN_MAX 64

struct keyd_vault {
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char sealed[VAULT_PIN_MAX + crypto_secretbox_MACBYTES];
    size_t sealed_len;
};

static int vault_master_key(unsigned char *out, const char *passphrase, size_t passphrase_len,
                            const struct keyd_vault *vault)
{
    unsigned char master[crypto_secretbox_KEYBYTES];

    if (crypto_pwhash(master, sizeof master, passphrase, passphrase_len, vault->salt,
                      crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        log_err("vault: key derivation ran out of memory");
        return KEYD_ERR_NOMEM;
    }
    memcpy(out, master, sizeof master);
    sodium_memzero(master, sizeof master);
    return KEYD_OK;
}

static int vault_parse(const struct keyd_buf *file, struct keyd_vault *vault)
{
    const size_t header = 4 + sizeof vault->salt + sizeof vault->nonce;
    if (file->len <= header || file->len - header > sizeof vault->sealed)
        return KEYD_ERR_ARGS;
    if (memcmp(file->data, VAULT_MAGIC, 4) != 0)
        return KEYD_ERR_ARGS;
    memcpy(vault->salt, file->data + 4, sizeof vault->salt);
    memcpy(vault->nonce, file->data + 4 + sizeof vault->salt, sizeof vault->nonce);
    vault->sealed_len = file->len - header;
    memcpy(vault->sealed, file->data + header, vault->sealed_len);
    return KEYD_OK;
}

int keyd_vault_store_pin(const char *path, const char *passphrase, const char *pin)
{
    struct keyd_vault vault;
    unsigned char master[crypto_secretbox_KEYBYTES];
    size_t plain_len = strlen(pin);
    const unsigned char *plain = (const unsigned char *)pin;

    if (plain_len == 0 || plain_len > VAULT_PIN_MAX)
        return KEYD_ERR_ARGS;
    randombytes_buf(vault.salt, sizeof vault.salt);
    randombytes_buf(vault.nonce, sizeof vault.nonce);
    int rc = vault_master_key(master, passphrase, strlen(passphrase), &vault);
    if (rc != KEYD_OK)
        return rc;

    crypto_secretbox_easy(vault.sealed, plain, plain_len, vault.nonce, master);
    vault.sealed_len = plain_len + crypto_secretbox_MACBYTES;
    sodium_memzero(master, sizeof master);

    struct keyd_buf out = { 0 };
    rc = keyd_buf_append(&out, VAULT_MAGIC, 4);
    if (rc == KEYD_OK)
        rc = keyd_buf_append(&out, vault.salt, sizeof vault.salt);
    if (rc == KEYD_OK)
        rc = keyd_buf_append(&out, vault.nonce, sizeof vault.nonce);
    if (rc == KEYD_OK)
        rc = keyd_buf_append(&out, vault.sealed, vault.sealed_len);
    if (rc == KEYD_OK)
        rc = keyd_write_file(path, out.data, out.len, 0600);
    keyd_buf_free(&out);
    return rc;
}

int keyd_vault_unlock_pin(const char *path, const char *passphrase, char *pin, size_t pin_cap)
{
    struct keyd_buf file = { 0 };
    struct keyd_vault vault;
    unsigned char master[crypto_secretbox_KEYBYTES];

    int rc = keyd_read_file(path, 4096, &file);
    if (rc == KEYD_OK)
        rc = vault_parse(&file, &vault);
    keyd_buf_free(&file);
    if (rc != KEYD_OK) {
        log_err("vault: %s is missing or damaged", path);
        return rc;
    }
    if (vault.sealed_len - crypto_secretbox_MACBYTES >= pin_cap)
        return KEYD_ERR_ARGS;

    rc = vault_master_key(master, passphrase, strlen(passphrase), &vault);
    if (rc != KEYD_OK)
        return rc;
    int opened = crypto_secretbox_open_easy((unsigned char *)pin, vault.sealed, vault.sealed_len, vault.nonce, master);
    sodium_memzero(master, sizeof master);
    if (opened != 0) {
        log_warn("vault: passphrase rejected");
        return KEYD_ERR_AUTH;
    }
    pin[vault.sealed_len - crypto_secretbox_MACBYTES] = '\0';
    return KEYD_OK;
}
