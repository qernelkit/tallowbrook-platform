/*
 * AES-128 in CTR mode written on the AES-NI round instructions, so a depot NVR can encrypt 16 camera
 * streams on one core. The key schedule uses _mm_aeskeygenassist_si128; each block is ten
 * _mm_aesenc/_mm_aesenclast rounds over the counter.
 */
#include "edgeclip.h"

#include <immintrin.h>
#include <string.h>
#include <wmmintrin.h>

static __m128i expand_step(__m128i key, __m128i gen)
{
    gen = _mm_shuffle_epi32(gen, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, gen);
}

static void expand_key(const uint8_t key[16], __m128i rk[11])
{
    rk[0] = _mm_loadu_si128((const __m128i *)key);
    rk[1] = expand_step(rk[0], _mm_aeskeygenassist_si128(rk[0], 0x01));
    rk[2] = expand_step(rk[1], _mm_aeskeygenassist_si128(rk[1], 0x02));
    rk[3] = expand_step(rk[2], _mm_aeskeygenassist_si128(rk[2], 0x04));
    rk[4] = expand_step(rk[3], _mm_aeskeygenassist_si128(rk[3], 0x08));
    rk[5] = expand_step(rk[4], _mm_aeskeygenassist_si128(rk[4], 0x10));
    rk[6] = expand_step(rk[5], _mm_aeskeygenassist_si128(rk[5], 0x20));
    rk[7] = expand_step(rk[6], _mm_aeskeygenassist_si128(rk[6], 0x40));
    rk[8] = expand_step(rk[7], _mm_aeskeygenassist_si128(rk[7], 0x80));
    rk[9] = expand_step(rk[8], _mm_aeskeygenassist_si128(rk[8], 0x1b));
    rk[10] = expand_step(rk[9], _mm_aeskeygenassist_si128(rk[9], 0x36));
}

void clip_ctr_init(struct clip_ctr *ctx, const uint8_t key[16], const uint8_t iv[16])
{
    __m128i rk[11];
    expand_key(key, rk);
    for (int i = 0; i < 11; i++)
        _mm_storeu_si128((__m128i *)(ctx->round_keys + i * 16), rk[i]);
    memcpy(ctx->counter, iv, 16);
}

static __m128i encrypt_block(const struct clip_ctr *ctx, __m128i blk)
{
    const struct clip_ctr *ks = ctx;
    blk = _mm_xor_si128(blk, _mm_loadu_si128((const __m128i *)ks->round_keys));
    for (int r = 1; r < 10; r++)
        blk = _mm_aesenc_si128(blk, _mm_loadu_si128((const __m128i *)(ks->round_keys + r * 16)));
    return _mm_aesenclast_si128(blk, _mm_loadu_si128((const __m128i *)(ks->round_keys + 160)));
}

static __m128i bswap_be(__m128i x)
{
    const __m128i mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    return _mm_shuffle_epi8(x, mask);
}

void clip_ctr_xcrypt(struct clip_ctr *ctx, const uint8_t *in, uint8_t *out, size_t len)
{
    const __m128i ONE = _mm_set_epi64x(0, 1);
    __m128i ctr = bswap_be(_mm_loadu_si128((const __m128i *)ctx->counter));

    for (size_t off = 0; off < len; off += 16) {
        __m128i keystream = encrypt_block(ctx, bswap_be(ctr));
        size_t chunk = len - off < 16 ? len - off : 16;
        if (chunk == 16) {
            __m128i block = _mm_loadu_si128((const __m128i *)(in + off));
            _mm_storeu_si128((__m128i *)(out + off), _mm_xor_si128(block, keystream));
        } else {
            uint8_t ks[16];
            _mm_storeu_si128((__m128i *)ks, keystream);
            for (size_t i = 0; i < chunk; i++)
                out[off + i] = in[off + i] ^ ks[i];
        }
        ctr = _mm_add_epi64(ctr, ONE);
    }
    _mm_storeu_si128((__m128i *)ctx->counter, bswap_be(ctr));
}
