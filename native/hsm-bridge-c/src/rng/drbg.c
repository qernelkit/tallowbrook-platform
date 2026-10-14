/*
 * tbkeyd's own random generator for IVs, challenges and request ids. It is seeded from the
 * operating system and reseeds on the provider's schedule.
 */
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "keyd/crypto_api.h"
#include "keyd/keyd.h"
#include "util/log.h"

static const char PERSONALISATION[] = "tbkeyd";

static EVP_RAND_CTX *rng_ctx;
static unsigned long drbg_generate_calls;
int keyd_rng_init(void)
{
    EVP_RAND *rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
    if (rand == NULL) {
        log_openssl_errors("rng: fetch");
        return KEYD_ERR_LIB;
    }
    rng_ctx = EVP_RAND_CTX_new(rand, NULL);
    EVP_RAND_free(rand);
    if (rng_ctx == NULL)
        return KEYD_ERR_LIB;

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, (char *)"AES-256-CTR", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_RAND_instantiate(rng_ctx, 256, 0, (const unsigned char *)PERSONALISATION, sizeof PERSONALISATION - 1,
                             params) != 1) {
        log_openssl_errors("rng: instantiate");
        EVP_RAND_CTX_free(rng_ctx);
        rng_ctx = NULL;
        return KEYD_ERR_LIB;
    }
    return KEYD_OK;
}

int keyd_rng_bytes(unsigned char *out, size_t len)
{
    if (rng_ctx == NULL)
        return KEYD_ERR_ARGS;
    while (len > 0) {
        size_t chunk = len > 4096 ? 4096 : len;
        if (EVP_RAND_generate(rng_ctx, out, chunk, 256, 0, NULL, 0) != 1)
            return KEYD_ERR_LIB;
        out += chunk;
        len -= chunk;
        drbg_generate_calls++;
    }
    return KEYD_OK;
}

unsigned long keyd_rng_calls(void)
{
    return drbg_generate_calls;
}

void keyd_rng_free(void)
{
    EVP_RAND_CTX_free(rng_ctx);
    rng_ctx = NULL;
}
