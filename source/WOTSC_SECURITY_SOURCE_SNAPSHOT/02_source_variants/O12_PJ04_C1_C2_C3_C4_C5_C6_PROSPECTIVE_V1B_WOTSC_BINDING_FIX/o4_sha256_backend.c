#include "o4_sha256_backend.h"

#include <stdint.h>
#include <string.h>

#if defined(__aarch64__) && defined(__ARM_FEATURE_SHA2)
#include <arm_neon.h>
#define O4_HAVE_ARMV8_SHA2 1
#else
#include <openssl/sha.h>
#define O4_HAVE_ARMV8_SHA2 0
#endif

#if O4_HAVE_ARMV8_SHA2
static const uint32_t o4_k[64] = {
    0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,
    0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
    0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,
    0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
    0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,
    0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
    0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,
    0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
    0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,
    0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
    0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,
    0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
    0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,
    0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
    0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,
    0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

static void o4_sha256_compress(uint32_t state[8], const unsigned char block[64])
{
    uint32x4_t s0 = vld1q_u32(state);
    uint32x4_t s1 = vld1q_u32(state + 4);
    uint32x4_t save0 = s0;
    uint32x4_t save1 = s1;
    uint32x4_t m0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 0)));
    uint32x4_t m1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 16)));
    uint32x4_t m2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 32)));
    uint32x4_t m3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 48)));
    uint32x4_t t0, old0;

#define O4_ROUND(MSG, OFF) do { \
    t0 = vaddq_u32((MSG), vld1q_u32(o4_k + (OFF))); \
    old0 = s0; \
    s0 = vsha256hq_u32(s0, s1, t0); \
    s1 = vsha256h2q_u32(s1, old0, t0); \
} while (0)

    O4_ROUND(m0, 0);
    m0 = vsha256su0q_u32(m0, m1);
    m0 = vsha256su1q_u32(m0, m2, m3);

    O4_ROUND(m1, 4);
    m1 = vsha256su0q_u32(m1, m2);
    m1 = vsha256su1q_u32(m1, m3, m0);

    O4_ROUND(m2, 8);
    m2 = vsha256su0q_u32(m2, m3);
    m2 = vsha256su1q_u32(m2, m0, m1);

    O4_ROUND(m3, 12);
    m3 = vsha256su0q_u32(m3, m0);
    m3 = vsha256su1q_u32(m3, m1, m2);

    O4_ROUND(m0, 16);
    m0 = vsha256su0q_u32(m0, m1);
    m0 = vsha256su1q_u32(m0, m2, m3);

    O4_ROUND(m1, 20);
    m1 = vsha256su0q_u32(m1, m2);
    m1 = vsha256su1q_u32(m1, m3, m0);

    O4_ROUND(m2, 24);
    m2 = vsha256su0q_u32(m2, m3);
    m2 = vsha256su1q_u32(m2, m0, m1);

    O4_ROUND(m3, 28);
    m3 = vsha256su0q_u32(m3, m0);
    m3 = vsha256su1q_u32(m3, m1, m2);

    O4_ROUND(m0, 32);
    m0 = vsha256su0q_u32(m0, m1);
    m0 = vsha256su1q_u32(m0, m2, m3);

    O4_ROUND(m1, 36);
    m1 = vsha256su0q_u32(m1, m2);
    m1 = vsha256su1q_u32(m1, m3, m0);

    O4_ROUND(m2, 40);
    m2 = vsha256su0q_u32(m2, m3);
    m2 = vsha256su1q_u32(m2, m0, m1);

    O4_ROUND(m3, 44);
    m3 = vsha256su0q_u32(m3, m0);
    m3 = vsha256su1q_u32(m3, m1, m2);

    O4_ROUND(m0, 48);
    O4_ROUND(m1, 52);
    O4_ROUND(m2, 56);
    O4_ROUND(m3, 60);

#undef O4_ROUND

    s0 = vaddq_u32(s0, save0);
    s1 = vaddq_u32(s1, save1);
    vst1q_u32(state, s0);
    vst1q_u32(state + 4, s1);
}

static void o4_store_be32(unsigned char *out, uint32_t x)
{
    out[0] = (unsigned char)(x >> 24);
    out[1] = (unsigned char)(x >> 16);
    out[2] = (unsigned char)(x >> 8);
    out[3] = (unsigned char)x;
}
#endif

int o4_sha256_digest(unsigned char out[32], const unsigned char *in, size_t inlen)
{
#if O4_HAVE_ARMV8_SHA2
    uint32_t state[8] = {
        0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
        0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U
    };
    const unsigned char *p = in;
    size_t remaining = inlen;
    unsigned char tail[128];
    size_t used;
    uint64_t bitlen;
    int i;

    while (remaining >= 64U) {
        o4_sha256_compress(state, p);
        p += 64U;
        remaining -= 64U;
    }

    memset(tail, 0, sizeof(tail));
    if (remaining != 0U) {
        memcpy(tail, p, remaining);
    }
    tail[remaining] = 0x80U;
    used = (remaining < 56U) ? 64U : 128U;
    bitlen = ((uint64_t)inlen) * 8U;
    tail[used - 8] = (unsigned char)(bitlen >> 56);
    tail[used - 7] = (unsigned char)(bitlen >> 48);
    tail[used - 6] = (unsigned char)(bitlen >> 40);
    tail[used - 5] = (unsigned char)(bitlen >> 32);
    tail[used - 4] = (unsigned char)(bitlen >> 24);
    tail[used - 3] = (unsigned char)(bitlen >> 16);
    tail[used - 2] = (unsigned char)(bitlen >> 8);
    tail[used - 1] = (unsigned char)bitlen;

    o4_sha256_compress(state, tail);
    if (used == 128U) {
        o4_sha256_compress(state, tail + 64U);
    }

    for (i = 0; i < 8; ++i) {
        o4_store_be32(out + 4 * i, state[i]);
    }
    return 0;
#else
    return SHA256(in, inlen, out) == NULL ? -1 : 0;
#endif
}

const char *o4_sha256_backend_name(void)
{
#if O4_HAVE_ARMV8_SHA2
    return "ARMV8_SHA2_INTRINSICS";
#else
    return "OPENSSL_FALLBACK";
#endif
}

int o4_sha256_armv8_active(void)
{
    return O4_HAVE_ARMV8_SHA2;
}
