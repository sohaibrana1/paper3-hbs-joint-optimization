#ifndef XMSS_WOTSC_H
#define XMSS_WOTSC_H

#include <stdint.h>

#include "params.h"

#define WOTSC_N_BYTES           32U
#define WOTSC_W                 16U
#define WOTSC_LOG_W             4U

#define WOTSC_Z                 0U
#define WOTSC_ELL               64U
#define WOTSC_FIXED_SUM         480U

#define WOTSC_COUNTER_BYTES     4U

#define WOTSC_CHAIN_BYTES       (WOTSC_ELL * WOTSC_N_BYTES)
#define WOTSC_PK_BYTES          WOTSC_CHAIN_BYTES
#define WOTSC_SIG_BYTES         (WOTSC_COUNTER_BYTES + WOTSC_CHAIN_BYTES)

#define XMSS_ADDR_TYPE_WOTSC_GRIND 7U

#define WOTSC_SUCCESS                    0
#define WOTSC_ERR_INVALID_ARGUMENT      -1
#define WOTSC_ERR_UNSUPPORTED_PROFILE   -2
#define WOTSC_ERR_HASH                  -3
#define WOTSC_ERR_GRINDING_EXHAUSTED    -4
#define WOTSC_ERR_INVALID_COUNTER       -5
#define WOTSC_ERR_CHAIN                 -6

/*
 * Standalone WOTS+C public-key generation.
 *
 * pk must provide WOTSC_PK_BYTES bytes.
 */
int wotsc_pkgen(const xmss_params *params,
                unsigned char *pk,
                const unsigned char *seed,
                const unsigned char *pub_seed,
                const uint32_t addr[8]);

/*
 * Standalone WOTS+C signing.
 *
 * msg is exactly params->n bytes for the initial profile.
 *
 * sig must provide WOTSC_SIG_BYTES bytes.
 *
 * selected_counter may be NULL.
 */
int wotsc_sign(const xmss_params *params,
               unsigned char *sig,
               uint32_t *selected_counter,
               const unsigned char *msg,
               const unsigned char *seed,
               const unsigned char *pub_seed,
               const uint32_t addr[8]);

/*
 * Recover the standalone WOTS+C public key from a signature.
 *
 * pk must provide WOTSC_PK_BYTES bytes.
 */
int wotsc_pk_from_sig(const xmss_params *params,
                      unsigned char *pk,
                      const unsigned char *sig,
                      const unsigned char *msg,
                      const unsigned char *pub_seed,
                      const uint32_t addr[8]);


/*
 * PJ04 streaming adapter API.
 *
 * WOTS+C cryptographic semantics remain authoritative in wotsc.c.
 */
int wotsc_terminal_pkgen(
    const xmss_params *params,
    unsigned char *terminal,
    const unsigned char *seed,
    const unsigned char *pub_seed,
    const uint32_t addr[8],
    uint32_t chain_index);

int wotsc_prepare_verification(
    const xmss_params *params,
    const unsigned char *sig,
    const unsigned char *msg,
    const unsigned char *pub_seed,
    const uint32_t addr[8],
    uint32_t *counter,
    unsigned int *digits);

int wotsc_terminal_from_sig(
    const xmss_params *params,
    unsigned char *terminal,
    const unsigned char *sig,
    const unsigned char *pub_seed,
    const uint32_t addr[8],
    const unsigned int *digits,
    uint32_t chain_index);

#endif
