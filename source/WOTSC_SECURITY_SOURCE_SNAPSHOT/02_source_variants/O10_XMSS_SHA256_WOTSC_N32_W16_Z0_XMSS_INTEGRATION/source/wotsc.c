#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "params.h"
#include "hash.h"
#include "hash_address.h"
#include "instrumentation.h"
#include "wotsc.h"

static int wotsc_validate_profile(const xmss_params *params)
{
    if (params == NULL) {
        return WOTSC_ERR_INVALID_ARGUMENT;
    }

    if (params->n != WOTSC_N_BYTES ||
        params->wots_w != WOTSC_W ||
        params->wots_log_w != WOTSC_LOG_W ||
        params->wots_len1 != WOTSC_ELL) {
        return WOTSC_ERR_UNSUPPORTED_PROFILE;
    }

    return WOTSC_SUCCESS;
}

static void wotsc_store_u32_be(unsigned char out[WOTSC_COUNTER_BYTES],
                               uint32_t value)
{
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)value;
}

static uint32_t wotsc_load_u32_be(
    const unsigned char in[WOTSC_COUNTER_BYTES])
{
    return
        ((uint32_t)in[0] << 24) |
        ((uint32_t)in[1] << 16) |
        ((uint32_t)in[2] << 8) |
        ((uint32_t)in[3]);
}

/*
 * Convert the 32-byte digest to 64 base-16 digits.
 *
 * The most-significant nibble is emitted first.
 */
static void wotsc_base16(unsigned int digits[WOTSC_ELL],
                         const unsigned char digest[WOTSC_N_BYTES])
{
    unsigned int i;

    for (i = 0U; i < WOTSC_N_BYTES; i++) {
        digits[2U * i] =
            (unsigned int)((digest[i] >> 4) & 0x0FU);

        digits[(2U * i) + 1U] =
            (unsigned int)(digest[i] & 0x0FU);
    }
}

static unsigned int wotsc_digit_sum(
    const unsigned int digits[WOTSC_ELL])
{
    unsigned int i;
    unsigned int sum = 0U;

    for (i = 0U; i < WOTSC_ELL; i++) {
        sum += digits[i];
    }

    return sum;
}

/*
 * Build the dedicated WOTS+C grinding address.
 *
 * Existing XMSS address:
 *
 *   word 0 = layer
 *   word 1 = tree high
 *   word 2 = tree low
 *   word 3 = type
 *   word 4 = OTS
 *   word 5 = chain/tree-height
 *   word 6 = hash/tree-index
 *   word 7 = key/mask
 *
 * For type 7 we retain layer/tree/OTS, place the counter
 * in word 5, and zero words 6 and 7.
 */
static void wotsc_build_grind_addr(uint32_t out[8],
                                   const uint32_t in[8],
                                   uint32_t counter)
{
    memcpy(out, in, 8U * sizeof(uint32_t));

    set_type(out, XMSS_ADDR_TYPE_WOTSC_GRIND);

    set_chain_addr(out, counter);
    set_hash_addr(out, 0U);
    set_key_and_mask(out, 0U);
}

/*
 * Compute the deterministic WOTS+C grinding digest for one counter.
 *
 * Frozen byte layout:
 *
 * domain[19]
 * || pub_seed[32]
 * || serialized grinding address[32]
 * || message digest[32]
 */
static int wotsc_digest_for_counter(
    const xmss_params *params,
    unsigned char digest[WOTSC_N_BYTES],
    unsigned int digits[WOTSC_ELL],
    const unsigned char *msg,
    const unsigned char *pub_seed,
    const uint32_t addr[8],
    uint32_t counter)
{
    uint32_t grind_addr[8];

    if (params == NULL ||
        digest == NULL ||
        digits == NULL ||
        msg == NULL ||
        pub_seed == NULL ||
        addr == NULL) {
        return WOTSC_ERR_INVALID_ARGUMENT;
    }

    /*
     * WOTS+C message grinding uses a dedicated tweak/address.
     *
     * The public seed is the public parameter/key for the
     * existing XMSS tweakable-hash construction.
     *
     * The type-7 address uniquely separates this operation
     * from ordinary WOTS chains, L-trees and Merkle hashing.
     *
     * The candidate counter is encoded into address word 5.
     */
    wotsc_build_grind_addr(
        grind_addr,
        addr,
        counter
    );

    /*
     * Reuse the existing XMSS tweakable hash.
     *
     * Logical construction:
     *
     *     digest =
     *         thash_f(
     *             pub_seed,
     *             type7_address(counter),
     *             msg
     *         )
     *
     * thash_f() internally derives its key and bitmask from
     * pub_seed and the serialized address.
     */
    if (thash_f(
            params,
            digest,
            msg,
            pub_seed,
            grind_addr
        ) != 0) {
        return WOTSC_ERR_HASH;
    }

    wotsc_base16(
        digits,
        digest
    );

    return WOTSC_SUCCESS;
}

static int wotsc_find_counter(
    const xmss_params *params,
    uint32_t *selected_counter,
    unsigned int digits[WOTSC_ELL],
    const unsigned char *msg,
    const unsigned char *pub_seed,
    const uint32_t addr[8])
{
    unsigned char digest[WOTSC_N_BYTES];
    uint32_t counter = 0U;

    if (selected_counter == NULL ||
        digits == NULL) {
        return WOTSC_ERR_INVALID_ARGUMENT;
    }

    for (;;) {
        int rc = wotsc_digest_for_counter(
            params,
            digest,
            digits,
            msg,
            pub_seed,
            addr,
            counter
        );

        if (rc != WOTSC_SUCCESS) {
            return rc;
        }

        if (wotsc_digit_sum(digits) ==
            WOTSC_FIXED_SUM) {
            *selected_counter = counter;
            return WOTSC_SUCCESS;
        }

        if (counter == UINT32_MAX) {
            return WOTSC_ERR_GRINDING_EXHAUSTED;
        }

        counter++;
    }
}

/*
 * Derive one WOTS+C secret-chain start.
 *
 * This mirrors the existing WOTS+ expand_seed() contract:
 *
 * PRF_keygen(
 *     seed,
 *     pub_seed || ADRS
 * )
 */
static int wotsc_derive_chain_start(
    const xmss_params *params,
    unsigned char *out,
    const unsigned char *seed,
    const unsigned char *pub_seed,
    const uint32_t base_addr[8],
    uint32_t chain)
{
    unsigned char input[WOTSC_N_BYTES + 32U];
    uint32_t chain_addr[8];

    memcpy(
        chain_addr,
        base_addr,
        sizeof(chain_addr)
    );

    set_type(
        chain_addr,
        XMSS_ADDR_TYPE_OTS
    );

    set_chain_addr(
        chain_addr,
        chain
    );

    set_hash_addr(
        chain_addr,
        0U
    );

    set_key_and_mask(
        chain_addr,
        0U
    );

    memcpy(
        input,
        pub_seed,
        WOTSC_N_BYTES
    );

    addr_to_bytes(
        input + WOTSC_N_BYTES,
        chain_addr
    );

    if (prf_keygen(
            params,
            out,
            input,
            seed
        ) != 0) {
        return WOTSC_ERR_HASH;
    }

    return WOTSC_SUCCESS;
}

/*
 * Apply the standard XMSS/WOTS+ thash_f() chain machinery.
 */
static int wotsc_gen_chain(
    const xmss_params *params,
    unsigned char *out,
    const unsigned char *in,
    unsigned int start,
    unsigned int steps,
    const unsigned char *pub_seed,
    const uint32_t base_addr[8],
    uint32_t chain)
{
    uint32_t chain_addr[8];
    unsigned int i;

    if (params == NULL ||
        out == NULL ||
        in == NULL ||
        pub_seed == NULL ||
        base_addr == NULL) {
        return WOTSC_ERR_INVALID_ARGUMENT;
    }

    if (start > (WOTSC_W - 1U)) {
        return WOTSC_ERR_CHAIN;
    }

    if (steps > ((WOTSC_W - 1U) - start)) {
        return WOTSC_ERR_CHAIN;
    }

    memcpy(
        chain_addr,
        base_addr,
        sizeof(chain_addr)
    );

    set_type(
        chain_addr,
        XMSS_ADDR_TYPE_OTS
    );

    set_chain_addr(
        chain_addr,
        chain
    );

    memcpy(
        out,
        in,
        WOTSC_N_BYTES
    );

    for (i = start;
         i < (start + steps);
         i++) {

        set_hash_addr(
            chain_addr,
            i
        );

        HBS_COUNT_WOTS_CHAIN_STEP();

        if (thash_f(
                params,
                out,
                out,
                pub_seed,
                chain_addr
            ) != 0) {
            return WOTSC_ERR_HASH;
        }
    }

    return WOTSC_SUCCESS;
}

int wotsc_pkgen(const xmss_params *params,
                unsigned char *pk,
                const unsigned char *seed,
                const unsigned char *pub_seed,
                const uint32_t addr[8])
{
    uint32_t i;
    int rc;

    rc = wotsc_validate_profile(params);

    if (rc != WOTSC_SUCCESS) {
        return rc;
    }

    if (pk == NULL ||
        seed == NULL ||
        pub_seed == NULL ||
        addr == NULL) {
        return WOTSC_ERR_INVALID_ARGUMENT;
    }

    for (i = 0U; i < WOTSC_ELL; i++) {
        unsigned char *chain_out =
            pk + ((size_t)i * WOTSC_N_BYTES);

        rc = wotsc_derive_chain_start(
            params,
            chain_out,
            seed,
            pub_seed,
            addr,
            i
        );

        if (rc != WOTSC_SUCCESS) {
            return rc;
        }

        rc = wotsc_gen_chain(
            params,
            chain_out,
            chain_out,
            0U,
            WOTSC_W - 1U,
            pub_seed,
            addr,
            i
        );

        if (rc != WOTSC_SUCCESS) {
            return rc;
        }
    }

    return WOTSC_SUCCESS;
}

int wotsc_sign(const xmss_params *params,
               unsigned char *sig,
               uint32_t *selected_counter,
               const unsigned char *msg,
               const unsigned char *seed,
               const unsigned char *pub_seed,
               const uint32_t addr[8])
{
    unsigned int digits[WOTSC_ELL];
    uint32_t counter;
    uint32_t i;
    int rc;

    rc = wotsc_validate_profile(params);

    if (rc != WOTSC_SUCCESS) {
        return rc;
    }

    if (sig == NULL ||
        msg == NULL ||
        seed == NULL ||
        pub_seed == NULL ||
        addr == NULL) {
        return WOTSC_ERR_INVALID_ARGUMENT;
    }

    rc = wotsc_find_counter(
        params,
        &counter,
        digits,
        msg,
        pub_seed,
        addr
    );

    if (rc != WOTSC_SUCCESS) {
        return rc;
    }

    wotsc_store_u32_be(
        sig,
        counter
    );

    for (i = 0U; i < WOTSC_ELL; i++) {
        unsigned char *chain_sig =
            sig +
            WOTSC_COUNTER_BYTES +
            ((size_t)i * WOTSC_N_BYTES);

        rc = wotsc_derive_chain_start(
            params,
            chain_sig,
            seed,
            pub_seed,
            addr,
            i
        );

        if (rc != WOTSC_SUCCESS) {
            return rc;
        }

        rc = wotsc_gen_chain(
            params,
            chain_sig,
            chain_sig,
            0U,
            digits[i],
            pub_seed,
            addr,
            i
        );

        if (rc != WOTSC_SUCCESS) {
            return rc;
        }
    }

    if (selected_counter != NULL) {
        *selected_counter = counter;
    }

    return WOTSC_SUCCESS;
}

int wotsc_pk_from_sig(const xmss_params *params,
                      unsigned char *pk,
                      const unsigned char *sig,
                      const unsigned char *msg,
                      const unsigned char *pub_seed,
                      const uint32_t addr[8])
{
    unsigned char digest[WOTSC_N_BYTES];
    unsigned int digits[WOTSC_ELL];

    uint32_t counter;
    uint32_t i;

    int rc;

    rc = wotsc_validate_profile(params);

    if (rc != WOTSC_SUCCESS) {
        return rc;
    }

    if (pk == NULL ||
        sig == NULL ||
        msg == NULL ||
        pub_seed == NULL ||
        addr == NULL) {
        return WOTSC_ERR_INVALID_ARGUMENT;
    }

    counter = wotsc_load_u32_be(sig);

    rc = wotsc_digest_for_counter(
        params,
        digest,
        digits,
        msg,
        pub_seed,
        addr,
        counter
    );

    if (rc != WOTSC_SUCCESS) {
        return rc;
    }

    if (wotsc_digit_sum(digits) !=
        WOTSC_FIXED_SUM) {
        return WOTSC_ERR_INVALID_COUNTER;
    }

    for (i = 0U; i < WOTSC_ELL; i++) {
        unsigned char *chain_pk =
            pk + ((size_t)i * WOTSC_N_BYTES);

        const unsigned char *chain_sig =
            sig +
            WOTSC_COUNTER_BYTES +
            ((size_t)i * WOTSC_N_BYTES);

        rc = wotsc_gen_chain(
            params,
            chain_pk,
            chain_sig,
            digits[i],
            (WOTSC_W - 1U) - digits[i],
            pub_seed,
            addr,
            i
        );

        if (rc != WOTSC_SUCCESS) {
            return rc;
        }
    }

    return WOTSC_SUCCESS;
}
