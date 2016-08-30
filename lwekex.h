/********************************************************************************************
 * LWE-Frodo: cryptographic library post-quantum key exchange from the learning with errors
 *            (LWE) problem
 *
 * Based on the paper:
 *     Joppe Bos, Craig Costello, Leo Ducas, Ilya Mironov, Michael Naehrig, Valeria
 *     Nikolaenko, Ananth Raghunathan, Douglas Stebila.  Frodo: Take off the ring!
 *     Practical, quantum-secure key exchange from LWE.  In ACM Conference on Computer
 *     and Communications Security (CCS) 2016, ACM, October, 2016.
 *         DOI:   http://dx.doi.org/10.1145/2976749.2978425
 *         Eprint http://eprint.iacr.org/2016/659
 *
 * Copyright (c) 2016 Joppe Bos, Leo Ducas, Ilya Mironov, Valeria Nikolaenko,
 *                    Ananth Raghunathan, Douglas Stebila
 *
 * Released under the MIT License; see LICENSE.txt for details.
 ********************************************************************************************/

/** \file lwekex.h
 * Interfaces for LWE key exchange algorithms.
 */

#ifndef HEADER_LWEKEX_H
#define HEADER_LWEKEX_H

#include <stdint.h>

typedef struct lwe_param_st {
	uint16_t *a;            // N x N
	uint16_t *a_transpose;  // N x N
	uint8_t *seed;  // 256 bits for seed
} LWE_PARAM;

typedef struct lwe_pub_st {
	LWE_PARAM *param;
	unsigned char *b;  // packed public key
} LWE_PUB;

typedef struct lwe_pair_st {
	LWE_PUB *pub;
	uint16_t *s;  // for Server (N x N_BAR), for Client (N_BAR x N)
} LWE_PAIR;

typedef struct lwe_rec_st {
	unsigned char *c;  // at least N_BAR * N_BAR bits
} LWE_REC;

/* Allocate and deallocate parameters, public keys, private key / public key
 * pairs, and reconciliation data structures */
LWE_PARAM *LWE_PARAM_new(void);
void LWE_PARAM_free(LWE_PARAM *param);

LWE_PUB *LWE_PUB_new(void);
void LWE_PUB_free(LWE_PUB *pub);

LWE_PAIR *LWE_PAIR_new(void);
void LWE_PAIR_free(LWE_PAIR *pair);

LWE_REC *LWE_REC_new(void);
void LWE_REC_free(LWE_REC *rec);

/* Convert public keys and reconciliation data structures from/to binary */
LWE_PUB *o2i_LWE_PUB(LWE_PUB **pub, const unsigned char *in, long len);
int i2o_LWE_PUB(LWE_PUB *pub, unsigned char **out);
LWE_REC *o2i_LWE_REC(LWE_REC **rec, const unsigned char *in, long len);
int i2o_LWE_REC(LWE_REC *rec, unsigned char **out);

LWE_PUB *LWE_PAIR_get_publickey(LWE_PAIR *pair);

/* Generate key pair */
int LWE_PAIR_generate_key(LWE_PAIR *key, char isForServer, uint8_t *seed);

/* Compute shared secret values */
int LWEKEX_compute_key_alice(
    void *out, size_t outlen, const LWE_PUB *peer_pub_key,
    const LWE_REC *peer_reconciliation, const LWE_PAIR *priv_pub_key,
    uint16_t *w);
int LWEKEX_compute_key_bob(void *out, size_t outlen, LWE_REC *reconciliation,
                           const LWE_PUB *peer_pub_key,
                           const LWE_PAIR *priv_pub_key,
                           uint16_t *v);

#endif
