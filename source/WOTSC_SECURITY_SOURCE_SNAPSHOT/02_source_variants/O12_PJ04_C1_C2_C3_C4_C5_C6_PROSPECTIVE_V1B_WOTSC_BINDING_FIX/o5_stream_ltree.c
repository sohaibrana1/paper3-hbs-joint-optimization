#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hash.h"
#include "hash_address.h"
#include "params.h"
#include "utils.h"
#include "o5_stream_ltree.h"
#include "wotsc.h"

static void o5_gen_chain(const xmss_params *params,
                         unsigned char *out,
                         const unsigned char *in,
                         unsigned int start,
                         unsigned int steps,
                         const unsigned char *pub_seed,
                         uint32_t addr[8])
{
    uint32_t i;
    memcpy(out, in, params->n);
    for (i = start; i < start + steps && i < params->wots_w; i++) {
        set_hash_addr(addr, i);
        thash_f(params, out, out, pub_seed, addr);
    }
}

static void o5_base_w(const xmss_params *params,
                      int *output,
                      int out_len,
                      const unsigned char *input)
{
    int in = 0;
    int out = 0;
    unsigned char total = 0;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in++];
            bits += 8;
        }
        bits -= (int)params->wots_log_w;
        output[out++] = (total >> bits) & (params->wots_w - 1);
    }
}

static void o5_wots_checksum(const xmss_params *params,
                             int *csum_base_w,
                             const int *msg_base_w)
{
    int csum = 0;
    unsigned int i;
    const size_t csum_len =
        (params->wots_len2 * params->wots_log_w + 7U) / 8U;
    unsigned char csum_bytes[csum_len];

    for (i = 0; i < params->wots_len1; i++) {
        csum += (int)params->wots_w - 1 - msg_base_w[i];
    }

    csum <<= 8 - ((params->wots_len2 * params->wots_log_w) % 8);
    ull_to_bytes(csum_bytes, (unsigned int)sizeof(csum_bytes),
                 (unsigned long long)csum);
    o5_base_w(params, csum_base_w, (int)params->wots_len2, csum_bytes);
}

static void o5_chain_lengths(const xmss_params *params,
                             int *lengths,
                             const unsigned char *msg)
{
    o5_base_w(params, lengths, (int)params->wots_len1, msg);
    o5_wots_checksum(params, lengths + params->wots_len1, lengths);
}

unsigned int o5_ltree_levels(const xmss_params *params)
{
    unsigned int levels = 1;
    unsigned int l = params->wots_len;
    while (l > 1U) {
        l = (l + 1U) >> 1;
        levels++;
    }
    return levels;
}

/*
 * Fold one node into a compact stack.  Equal-height adjacent nodes are hashed
 * exactly as the baseline l_tree() would hash them at that level.
 */
static int o5_push_node(const xmss_params *params,
                        unsigned char *stack,
                        uint32_t *heights,
                        uint32_t *indices,
                        unsigned int *top,
                        unsigned int levels,
                        unsigned char *node,
                        uint32_t node_height,
                        uint32_t node_index,
                        const unsigned char *pub_seed,
                        uint32_t ltree_addr[8])
{
    unsigned char pair[2U * params->n];

    while (*top > 0U && heights[*top - 1U] == node_height) {
        const uint32_t left_index = indices[*top - 1U];
        if (left_index + 1U != node_index || (left_index & 1U) != 0U) {
            return -1;
        }
        memcpy(pair, stack + (*top - 1U) * params->n, params->n);
        memcpy(pair + params->n, node, params->n);
        set_tree_height(ltree_addr, node_height);
        set_tree_index(ltree_addr, left_index >> 1);
        thash_h(params, node, pair, pub_seed, ltree_addr);
        (*top)--;
        node_height++;
        node_index >>= 1;
    }

    if (*top >= levels) {
        return -1;
    }
    memcpy(stack + (*top) * params->n, node, params->n);
    heights[*top] = node_height;
    indices[*top] = node_index;
    (*top)++;
    return 0;
}

/*
 * Resolve the right-edge odd nodes.  Baseline l_tree() promotes an unpaired
 * final node unchanged to the next level.  We model that promotion by raising
 * its logical height/index until it can be combined with the node to its left.
 */
static int o5_finish_tree(const xmss_params *params,
                          unsigned char *leaf,
                          unsigned char *stack,
                          uint32_t *heights,
                          uint32_t *indices,
                          unsigned int *top,
                          const unsigned char *pub_seed,
                          uint32_t ltree_addr[8])
{
    unsigned char pair[2U * params->n];

    if (*top == 0U) {
        return -1;
    }

    while (*top > 1U) {
        const unsigned int r = *top - 1U;
        const unsigned int l = *top - 2U;
        uint32_t rh = heights[r];
        uint32_t ri = indices[r];
        const uint32_t lh = heights[l];
        const uint32_t li = indices[l];

        if (rh > lh) {
            return -1;
        }
        while (rh < lh) {
            rh++;
            ri >>= 1;
        }
        if (li + 1U != ri || (li & 1U) != 0U) {
            return -1;
        }

        memcpy(pair, stack + l * params->n, params->n);
        memcpy(pair + params->n, stack + r * params->n, params->n);
        set_tree_height(ltree_addr, lh);
        set_tree_index(ltree_addr, li >> 1);
        thash_h(params, stack + l * params->n, pair, pub_seed, ltree_addr);
        heights[l] = lh + 1U;
        indices[l] = li >> 1;
        (*top)--;
    }

    memcpy(leaf, stack, params->n);
    return 0;
}

int o5_gen_leaf_wots_stream(const xmss_params *params,
                            unsigned char *leaf,
                            const unsigned char *sk_seed,
                            const unsigned char *pub_seed,
                            uint32_t ltree_addr[8],
                            uint32_t ots_addr[8])
{
    const unsigned int levels = o5_ltree_levels(params);
    unsigned char stack[levels * params->n];
    uint32_t heights[levels];
    uint32_t indices[levels];
    unsigned char node[params->n];
    unsigned char seed_buf[params->n + 32U];
    unsigned int top = 0;
    uint32_t i;

    memcpy(seed_buf, pub_seed, params->n);

    for (i = 0; i < params->wots_len; i++) {
        /* Derive exactly the same WOTS private-chain element as expand_seed. */
        set_hash_addr(ots_addr, 0);
        set_key_and_mask(ots_addr, 0);
        set_chain_addr(ots_addr, i);
        addr_to_bytes(seed_buf + params->n, ots_addr);
        prf_keygen(params, node, seed_buf, sk_seed);

        set_chain_addr(ots_addr, i);
        o5_gen_chain(params, node, node, 0,
                     params->wots_w - 1U, pub_seed, ots_addr);

        if (o5_push_node(params, stack, heights, indices, &top, levels,
                         node, 0, i, pub_seed, ltree_addr) != 0) {
            return -1;
        }
    }

    return o5_finish_tree(params, leaf, stack, heights, indices, &top,
                          pub_seed, ltree_addr);
}

int o5_wots_leaf_from_sig_stream(const xmss_params *params,
                                 unsigned char *leaf,
                                 const unsigned char *sig,
                                 const unsigned char *msg,
                                 const unsigned char *pub_seed,
                                 uint32_t ltree_addr[8],
                                 uint32_t ots_addr[8])
{
    const unsigned int levels = o5_ltree_levels(params);
    unsigned char stack[levels * params->n];
    uint32_t heights[levels];
    uint32_t indices[levels];
    unsigned char node[params->n];
    int lengths[params->wots_len];
    unsigned int top = 0;
    uint32_t i;

    o5_chain_lengths(params, lengths, msg);

    for (i = 0; i < params->wots_len; i++) {
        set_chain_addr(ots_addr, i);
        o5_gen_chain(params, node, sig + i * params->n,
                     (unsigned int)lengths[i],
                     params->wots_w - 1U - (unsigned int)lengths[i],
                     pub_seed, ots_addr);

        if (o5_push_node(params, stack, heights, indices, &top, levels,
                         node, 0, i, pub_seed, ltree_addr) != 0) {
            return -1;
        }
    }

    return o5_finish_tree(params, leaf, stack, heights, indices, &top,
                          pub_seed, ltree_addr);
}

size_t o5_pkgen_explicit_scratch_bytes(const xmss_params *params)
{
    const size_t levels = o5_ltree_levels(params);
    return levels * params->n +
           levels * sizeof(uint32_t) * 2U +
           params->n +
           (params->n + 32U) +
           2U * params->n;
}

size_t o5_verify_explicit_scratch_bytes(const xmss_params *params)
{
    const size_t levels = o5_ltree_levels(params);
    const size_t csum_len =
        (params->wots_len2 * params->wots_log_w + 7U) / 8U;
    return levels * params->n +
           levels * sizeof(uint32_t) * 2U +
           params->n +
           2U * params->n +
           params->wots_len * sizeof(int) +
           csum_len;
}

size_t o5_baseline_pkgen_explicit_scratch_bytes(const xmss_params *params)
{
    /* gen_leaf_wots pk[] plus nested expand_seed buf[]. */
    return params->wots_sig_bytes + params->n + 32U;
}

size_t o5_baseline_verify_explicit_scratch_bytes(const xmss_params *params)
{
    const size_t csum_len =
        (params->wots_len2 * params->wots_log_w + 7U) / 8U;
    /* verifier wots_pk[] plus nested wots_pk_from_sig lengths/checksum. */
    return params->wots_sig_bytes +
           params->wots_len * sizeof(int) +
           csum_len;
}


int o5_gen_leaf_wotsc_stream(
    const xmss_params *params,
    unsigned char *leaf,
    const unsigned char *sk_seed,
    const unsigned char *pub_seed,
    uint32_t ltree_addr[8],
    uint32_t ots_addr[8])
{
    const unsigned int levels = o5_ltree_levels(params);
    unsigned char stack[levels * params->n];
    uint32_t heights[levels];
    uint32_t indices[levels];
    unsigned char node[params->n];
    unsigned int top = 0;
    uint32_t i;
    int rc;

    for (i = 0U; i < WOTSC_ELL; i++) {

        rc = wotsc_terminal_pkgen(
            params,
            node,
            sk_seed,
            pub_seed,
            ots_addr,
            i
        );

        if (rc != WOTSC_SUCCESS) {
            return -1;
        }

        if (o5_push_node(
                params,
                stack,
                heights,
                indices,
                &top,
                levels,
                node,
                0,
                i,
                pub_seed,
                ltree_addr
            ) != 0) {
            return -1;
        }
    }

    return o5_finish_tree(
        params,
        leaf,
        stack,
        heights,
        indices,
        &top,
        pub_seed,
        ltree_addr
    );
}


int o5_wotsc_leaf_from_sig_stream(
    const xmss_params *params,
    unsigned char *leaf,
    const unsigned char *sig,
    const unsigned char *msg,
    const unsigned char *pub_seed,
    uint32_t ltree_addr[8],
    uint32_t ots_addr[8])
{
    const unsigned int levels = o5_ltree_levels(params);
    unsigned char stack[levels * params->n];
    uint32_t heights[levels];
    uint32_t indices[levels];
    unsigned char node[params->n];
    unsigned int digits[WOTSC_ELL];
    uint32_t counter;
    unsigned int top = 0;
    uint32_t i;
    int rc;

    rc = wotsc_prepare_verification(
        params,
        sig,
        msg,
        pub_seed,
        ots_addr,
        &counter,
        digits
    );

    if (rc != WOTSC_SUCCESS) {
        return -1;
    }

    (void)counter;

    for (i = 0U; i < WOTSC_ELL; i++) {

        rc = wotsc_terminal_from_sig(
            params,
            node,
            sig,
            pub_seed,
            ots_addr,
            digits,
            i
        );

        if (rc != WOTSC_SUCCESS) {
            return -1;
        }

        if (o5_push_node(
                params,
                stack,
                heights,
                indices,
                &top,
                levels,
                node,
                0,
                i,
                pub_seed,
                ltree_addr
            ) != 0) {
            return -1;
        }
    }

    return o5_finish_tree(
        params,
        leaf,
        stack,
        heights,
        indices,
        &top,
        pub_seed,
        ltree_addr
    );
}

