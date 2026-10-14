/*
 * The gateway's DRBG, seeded from the SoC hardware RNG through the mbedTLS entropy module and
 * reseeded on the library's schedule. Everything that needs random bytes goes through gw_random().
 */
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include "gateway/gw.h"
#include "gateway/gw_log.h"

static mbedtls_entropy_context gw_entropy;
static mbedtls_ctr_drbg_context gw_drbg;
static int ready;

int gw_entropy_init(void)
{
    const unsigned char pers[] = "gwfw-rng-v3";
    mbedtls_entropy_init(&gw_entropy);
    mbedtls_ctr_drbg_init(&gw_drbg);
    int rc = mbedtls_ctr_drbg_seed(&gw_drbg, mbedtls_entropy_func, &gw_entropy, pers, sizeof pers - 1);
    if (rc != 0)
        return GW_LOG_ERR("rng: seed failed (-0x%04x)", (unsigned)-rc), GW_ERR_CRYPTO;
    GW_LOG("rng: entropy pool ready");
    ready = 1;
    return GW_OK;
}

int gw_random(uint8_t *out, size_t len)
{
    if (!ready)
        return GW_ERR_STATE;
    return mbedtls_ctr_drbg_random(&gw_drbg, out, len) == 0 ? GW_OK : GW_ERR_CRYPTO;
}

mbedtls_ctr_drbg_context *gw_drbg_ctx(void)
{
    return &gw_drbg;
}

void gw_entropy_free(void)
{
    mbedtls_ctr_drbg_free(&gw_drbg);
    mbedtls_entropy_free(&gw_entropy);
    ready = 0;
}
