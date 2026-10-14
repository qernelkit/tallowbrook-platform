/*
 * Link to the fuel-card terminals at the depot pumps (vendor: Petrolink, protocol T3). The back
 * office posts each sale; tbkeyd frames it for the terminal network. The vendor's frame format is
 * fixed: the body, the vendor digest of the body, an LRC, all encrypted with the vendor transport
 * key. Terminals drop frames without the digest field.
 */
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keyd/crypto_api.h"
#include "keyd/keyd.h"
#include "util/log.h"

#define T3_STX 0x02
#define T3_ETX 0x03
#define T3_MAX_ITEMS 8
#define T3_MAX_BODY 512

struct fuel_line_item {
    char product_code[9];
    char des[41]; /* product description */
    unsigned int litres_milli;
    unsigned int price_cents;
};

struct fuel_sale {
    char terminal_id[9];
    char card_pan_masked[20];
    unsigned int sale_no;
    size_t item_count;
    struct fuel_line_item items[T3_MAX_ITEMS];
};

struct fuelcard_profile {
    const char *vendor;
    const EVP_CIPHER *(*cipher)(void);
    size_t block;
};

/* The vendor publishes one transport key and IV for its whole terminal fleet. */
static const unsigned char FUELCARD_TRANSPORT_KEY[24] = { 0x4a, 0x91, 0x0e, 0xd7, 0x63, 0x2c, 0xb8, 0x15, 0xf2, 0x7d, 0x46, 0xa9, 0x0b, 0xe4, 0x38, 0x9f, 0xc5, 0x21, 0x7a, 0xd0, 0x6e, 0x13, 0xbc, 0x57 };
static const unsigned char FUELCARD_IV[8] = { 0x31, 0x52, 0x74, 0x96, 0xb8, 0xda, 0xfc, 0x1e };

static const struct fuelcard_profile FUELCARD_PROFILE = {
    .vendor = "Petrolink T3",
    .cipher = EVP_des_ede3_cbc,
    .block = 8,
};

/* Sale lines from the back office: "terminal|pan|sale_no|code:description:litres_milli:cents;..." */
static int parse_sale(const char *line, struct fuel_sale *sale)
{
    char buf[1024];
    char *save = NULL, *items, *item;

    memset(sale, 0, sizeof *sale);
    if (snprintf(buf, sizeof buf, "%s", line) >= (int)sizeof buf)
        return KEYD_ERR_ARGS;
    char *term = strtok_r(buf, "|", &save);
    char *pan = strtok_r(NULL, "|", &save);
    char *no = strtok_r(NULL, "|", &save);
    items = strtok_r(NULL, "|", &save);
    if (term == NULL || pan == NULL || no == NULL || items == NULL)
        return KEYD_ERR_ARGS;
    snprintf(sale->terminal_id, sizeof sale->terminal_id, "%s", term);
    snprintf(sale->card_pan_masked, sizeof sale->card_pan_masked, "%s", pan);
    sale->sale_no = (unsigned int)strtoul(no, NULL, 10);

    char *isave = NULL;
    for (item = strtok_r(items, ";", &isave); item != NULL; item = strtok_r(NULL, ";", &isave)) {
        if (sale->item_count == T3_MAX_ITEMS)
            return KEYD_ERR_ARGS;
        struct fuel_line_item *it = &sale->items[sale->item_count++];
        char *fsave = NULL;
        char *code = strtok_r(item, ":", &fsave);
        char *text = strtok_r(NULL, ":", &fsave);
        char *litres = strtok_r(NULL, ":", &fsave);
        char *cents = strtok_r(NULL, ":", &fsave);
        if (code == NULL || text == NULL || litres == NULL || cents == NULL)
            return KEYD_ERR_ARGS;
        snprintf(it->product_code, sizeof it->product_code, "%s", code);
        snprintf(it->des, sizeof it->des, "%s", text);
        it->litres_milli = (unsigned int)strtoul(litres, NULL, 10);
        it->price_cents = (unsigned int)strtoul(cents, NULL, 10);
    }
    return sale->item_count > 0 ? KEYD_OK : KEYD_ERR_ARGS;
}

/* Fixed-width body: terminal(8) sale_no(6) count(1) then per item code(8) desc(40) litres(7) cents(7). */
static size_t sale_body(const struct fuel_sale *sale, unsigned char *out, size_t cap)
{
    int n = snprintf((char *)out, cap, "%-8.8s%06u%1u", sale->terminal_id, sale->sale_no % 1000000,
                     (unsigned)sale->item_count);
    for (size_t i = 0; i < sale->item_count && n > 0 && (size_t)n < cap; i++) {
        const struct fuel_line_item *it = &sale->items[i];
        n += snprintf((char *)out + n, cap - (size_t)n, "%-8.8s%-40.40s%07u%07u", it->product_code, it->des,
                      it->litres_milli % 10000000, it->price_cents % 10000000);
    }
    return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

/* Appends the vendor digest and the LRC to the body. */
static int frame_trailer(unsigned char *frame, size_t frame_len, size_t cap, size_t *total)
{
    unsigned char sum[SHA_DIGEST_LENGTH];
    unsigned char lrc = 0;

    if (frame_len + sizeof sum + 1 > cap)
        return KEYD_ERR_ARGS;
    if (EVP_Digest(frame, frame_len, sum, NULL, EVP_sha1(), NULL) != 1)
        return KEYD_ERR_LIB;
    for (size_t i = 0; i < frame_len; i++)
        lrc ^= frame[i];
    memcpy(frame + frame_len, sum, sizeof sum);
    frame[frame_len + sizeof sum] = lrc;
    *total = frame_len + sizeof sum + 1;
    return KEYD_OK;
}

static int encrypt_frame(const unsigned char *frame, size_t frame_len, unsigned char *out, size_t *out_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, fin = 0, rc = KEYD_ERR_LIB;

    if (ctx == NULL)
        return KEYD_ERR_NOMEM;
    if (EVP_EncryptInit_ex2(ctx, FUELCARD_PROFILE.cipher(), FUELCARD_TRANSPORT_KEY, FUELCARD_IV, NULL) == 1
        && EVP_EncryptUpdate(ctx, out, &n, frame, (int)frame_len) == 1 && EVP_EncryptFinal_ex(ctx, out + n, &fin) == 1) {
        *out_len = (size_t)n + (size_t)fin;
        rc = KEYD_OK;
    }
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

static int decrypt_frame(const unsigned char *in, size_t in_len, unsigned char *out, size_t *out_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, fin = 0, rc = KEYD_ERR_LIB;

    if (ctx == NULL)
        return KEYD_ERR_NOMEM;
    if (EVP_DecryptInit_ex2(ctx, FUELCARD_PROFILE.cipher(), FUELCARD_TRANSPORT_KEY, FUELCARD_IV, NULL) == 1
        && EVP_DecryptUpdate(ctx, out, &n, in, (int)in_len) == 1 && EVP_DecryptFinal_ex(ctx, out + n, &fin) == 1) {
        *out_len = (size_t)n + (size_t)fin;
        rc = KEYD_OK;
    }
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int keyd_fuelcard_encode_sale(const char *sale_line, unsigned char *out, size_t out_cap, size_t *out_len)
{
    struct fuel_sale sale;
    unsigned char frame[T3_MAX_BODY + 32], sealed[T3_MAX_BODY + 48];
    size_t frame_len = 0, sealed_len = 0;

    int rc = parse_sale(sale_line, &sale);
    if (rc != KEYD_OK)
        return rc;
    size_t body_len = sale_body(&sale, frame, T3_MAX_BODY);
    if (body_len == 0)
        return KEYD_ERR_ARGS;
    if ((rc = frame_trailer(frame, body_len, sizeof frame, &frame_len)) != KEYD_OK)
        return rc;
    if ((rc = encrypt_frame(frame, frame_len, sealed, &sealed_len)) != KEYD_OK)
        return rc;
    if (out_cap < sealed_len + 4)
        return KEYD_ERR_ARGS;
    out[0] = T3_STX;
    out[1] = (unsigned char)(sealed_len >> 8);
    out[2] = (unsigned char)sealed_len;
    memcpy(out + 3, sealed, sealed_len);
    out[3 + sealed_len] = T3_ETX;
    *out_len = sealed_len + 4;
    log_debug("fuelcard: sale %u for terminal %s framed (%zu bytes) via %s", sale.sale_no, sale.terminal_id,
              *out_len, FUELCARD_PROFILE.vendor);
    return KEYD_OK;
}

/* Terminal replies carry a six-character authorisation code at the start of the body. */
int keyd_fuelcard_decode_reply(const unsigned char *in, size_t in_len, char *auth_code, size_t code_cap)
{
    unsigned char plain[T3_MAX_BODY + 48];
    size_t plain_len = 0;

    if (in_len < 5 || in[0] != T3_STX || in[in_len - 1] != T3_ETX || code_cap < 7)
        return KEYD_ERR_ARGS;
    size_t len = (size_t)in[1] << 8 | in[2];
    if (len + 4 != in_len || len > sizeof plain - FUELCARD_PROFILE.block || len % FUELCARD_PROFILE.block != 0)
        return KEYD_ERR_ARGS;
    int rc = decrypt_frame(in + 3, len, plain, &plain_len);
    if (rc != KEYD_OK)
        return rc;
    if (plain_len < 6 + SHA_DIGEST_LENGTH + 1)
        return KEYD_ERR_ARGS;
    memcpy(auth_code, plain, 6);
    auth_code[6] = '\0';
    return KEYD_OK;
}
