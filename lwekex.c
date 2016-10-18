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

/** \file lwekex.c
 * LWE key exchange algorithms.
 */

#include <string.h>
#include <openssl/rand.h>

#include "lwekex.h"

#include "lwe.c"
#include "lwe_noise.c"

// #define DEBUG_LOGS

int debug_printf(const char *format, ...) {
	va_list args;
	int ret = 0;
	va_start(args, format);
	ret = vprintf(format, args);
	va_end(args);
	return ret;
}

void binary_printf(uint64_t n, int bits_num) {
	int i;
	for (i = bits_num - 1; i >= 0; i--) {
		if ((n >> i) & 1) {
			printf("1");
		} else {
			printf("0");
		}
	}
}

/* Allocate and deallocate public parameters data structure */

LWE_PARAM *LWE_PARAM_new(void) {
	LWE_PARAM *ret;
	ret = (LWE_PARAM *)malloc(sizeof(LWE_PARAM));
	if (ret == NULL) {
		return (NULL);
	}
	// Instead of a, we will have the seed
	uint8_t *seed = (uint8_t *)malloc(LWE_SEED_LENGTH);
	memset((uint8_t *)seed, 0, LWE_SEED_LENGTH);
	ret->seed = (uint8_t *)seed;
	ret->a = NULL;            // was: (uint16_t *)lwe_a; generated on the fly now
	ret->a_transpose = NULL;  // was: (uint16_t *)lwe_a_transpose;
	/* Debug aid: setting A to the identify matrix
	int i, j;
	for (i = 0; i < LWE_N; i++)
	  for (j = 0; j < LWE_N; j++) {
	    if (i == j) {
	      ret->a[i * LWE_N + j] = 256;
	      ret->a_transpose[i * LWE_N + j] = 256;
	    } else {
	      ret->a[i * LWE_N + j] = 0;
	      ret->a_transpose[i * LWE_N + j] = 0;
	    }
	  }
	*/
	return (ret);
}

void LWE_PARAM_free(LWE_PARAM *r) {
	if (r == NULL) {
		return;
	}
	if (r->seed != NULL) {
		bzero(r->seed, LWE_SEED_LENGTH);
		free(r->seed);
		r->seed = NULL;
	}
	bzero((void *)r, sizeof(LWE_PARAM));
	free(r);
}

/* Allocate and deallocate public key data structure */

LWE_PUB *LWE_PUB_new(void) {
	LWE_PUB *ret;
	ret = (LWE_PUB *)malloc(sizeof(LWE_PUB));
	if (ret == NULL) {
		return (NULL);
	}
	ret->param = NULL;
	ret->b = (unsigned char *)malloc(LWE_PUB_LENGTH);
	return (ret);
}

void LWE_PUB_free(LWE_PUB *r) {
	if (r == NULL) {
		return;
	}
	LWE_PARAM_free(r->param);
	bzero(r->b, LWE_PUB_LENGTH);
	free(r->b);
	bzero((void *)r, sizeof(LWE_PUB));
	free(r);
}

/* Allocate and deallocate public key / private key pair data structure */
LWE_PAIR *LWE_PAIR_new(void) {
	LWE_PAIR *ret;
	ret = (LWE_PAIR *)malloc(sizeof(LWE_PAIR));
	if (ret == NULL) {
		return (NULL);
	}
	ret->pub = NULL;
	ret->s = (uint16_t *)malloc(LWE_N * LWE_N_BAR * sizeof(uint16_t));
	return (ret);
}

void LWE_PAIR_free(LWE_PAIR *r) {
	if (r == NULL) {
		return;
	}
	LWE_PUB_free(r->pub);
	bzero(r->s, LWE_N * LWE_N_BAR * sizeof(uint16_t));
	free(r->s);
	bzero((void *)r, sizeof(LWE_PAIR));
	free(r);
}

/* Allocate and deallocate reconciliation data structure */
LWE_REC *LWE_REC_new(void) {
	LWE_REC *ret;
	ret = (LWE_REC *)malloc(sizeof(LWE_REC));
	if (ret == NULL) {
		return (NULL);
	}
	ret->c = (unsigned char *)malloc(LWE_REC_HINT_LENGTH);
	if (ret->c == NULL) {
		return (NULL);
	}
	return (ret);
}

void LWE_REC_free(LWE_REC *r) {
	if (r == NULL) {
		return;
	}
	bzero(r->c, LWE_REC_HINT_LENGTH);
	free(r->c);
	bzero((void *)r, sizeof(LWE_REC));
	free(r);
}

/* Convert public keys data structures from/to binary */
LWE_PUB *o2i_LWE_PUB(LWE_PUB **pub, const unsigned char *in, long len) {
	if (pub == NULL) {
		return 0;
	}
	if (*pub == NULL && (*pub = LWE_PUB_new()) == NULL) {
		return 0;
	}
	if ((*pub)->param == NULL && ((*pub)->param = LWE_PARAM_new()) == NULL) {
		return 0;
	}

#ifdef DEBUG_LOGS
	debug_printf("-----> len %d, lwe_pub_length %d\n", len, LWE_PUB_LENGTH);
#endif
	if (len != LWE_PUB_LENGTH) {
		return 0;
	}

	memcpy((*pub)->b, in, LWE_PUB_LENGTH);

	return *pub;
}

int i2o_LWE_PUB(LWE_PUB *pub, unsigned char **out) {
	size_t buf_len = 0;
	int new_buffer = 0;

	if (pub == NULL) {
		return 0;
	}

	buf_len = LWE_PUB_LENGTH;

	if (out == NULL || buf_len == 0)
		/* out == NULL => just return the length of the octet string */
	{
		return buf_len;
	}

	if (*out == NULL) {
		if ((*out = OPENSSL_malloc(buf_len)) == NULL) {
			return 0;
		}
		new_buffer = 1;
	}

	memcpy(*out, pub->b, LWE_PUB_LENGTH);

	if (!new_buffer) {
		*out += buf_len;
	}
	return buf_len;
}

/* Convert reconciliation data structure from/to binary */

LWE_REC *o2i_LWE_REC(LWE_REC **rec, const unsigned char *in, long len) {
	if (rec == NULL) {
		return 0;
	}
	if (*rec == NULL && (*rec = LWE_REC_new()) == NULL) {
		return 0;
	}

	if (len != LWE_REC_HINT_LENGTH) {
		return 0;
	}
	memcpy((unsigned char *)((*rec)->c), in, len);

	return *rec;
}

int i2o_LWE_REC(LWE_REC *rec, unsigned char **out) {
	size_t buf_len = 0;
	int new_buffer = 0;

	if (rec == NULL) {
		return 0;
	}

	buf_len = LWE_REC_HINT_LENGTH;

	if (out == NULL || buf_len == 0)
		/* out == NULL => just return the length of the octet string */
	{
		return buf_len;
	}

	if (*out == NULL) {
		if ((*out = OPENSSL_malloc(buf_len)) == NULL) {
			return 0;
		}
		new_buffer = 1;
	}

	memcpy(*out, (unsigned char *)rec->c, buf_len);

	if (!new_buffer) {
		*out += buf_len;
	}
	return buf_len;
}

/* Get public key from a key pair */
LWE_PUB *LWE_PAIR_get_publickey(LWE_PAIR *pair) {
	if (pair == NULL) {
		return NULL;
	}
	return pair->pub;
}

/* Generate key pair */
int LWE_PAIR_generate_key(LWE_PAIR *key, char isForServer,
                          uint8_t *seed) {
	int ok = 0;

	uint16_t *e = NULL;

	key->pub = LWE_PUB_new();
	if (key->pub == NULL) {
		goto err;
	}

	key->pub->param = LWE_PARAM_new();
	if (key->pub->param == NULL) {
		goto err;
	}

	if (seed != NULL) {
		memcpy(key->pub->param->seed, seed, LWE_SEED_LENGTH);
	} else { // sample the seed using the standard PRNG
		RAND_bytes(key->pub->param->seed, LWE_SEED_LENGTH);
	}

	e = (uint16_t *)malloc(LWE_N * LWE_N_BAR * sizeof(uint16_t));
	if (e == NULL) {
		goto err;
	}

	LWE_SAMPLE_N(key->s, LWE_N * LWE_N_BAR);
	LWE_SAMPLE_N(e, LWE_N * LWE_N_BAR);

	// find min/max S
	int16_t signed_s_min = key->s[0], signed_s_max = key->s[0];
	int i;
	for (i = 0; i < LWE_N * LWE_N_BAR - 1; i++) {
		if ((int16_t)key->s[i] < signed_s_min) {
			signed_s_min = (int16_t)key->s[i];
		}
		if ((int16_t)key->s[i] > signed_s_max) {
			signed_s_max = (int16_t)key->s[i];
		}
	}
#ifdef DEBUG_LOGS
	debug_printf("  secret S in [%i, %i]\n", signed_s_min, signed_s_max);
	debug_printf("  secret S = ");
	debug_printf("%d %d ... %d\n", (int16_t)key->s[0], (int16_t)key->s[1],
	             (int16_t)key->s[LWE_N * LWE_N_BAR - 1]);

	debug_printf("  secret E = ");
	debug_printf("%d %d ... %d\n", (int16_t)e[0], (int16_t)e[1],
	             (int16_t)e[LWE_N * LWE_N_BAR - 1]);
#endif

	if (isForServer) {
		if (!lwe_key_gen_server_gen_a(key->pub->b, key->pub->param->seed, key->s,
		                              e)) {
			ok = 0;
			goto err;
		}
	} else {
		if (!lwe_key_gen_client_gen_a(key->pub->b, key->pub->param->seed, key->s,
		                              e)) {
			ok = 0;
			goto err;
		}
	}

	ok = 1;
	goto err;

err:
	if (e) {
		bzero(e, LWE_N * LWE_N_BAR * sizeof(uint16_t));
		free(e);
	}

	return (ok);
}

/* Compute shared secret values */
int LWEKEX_compute_key_alice(
    void *out, size_t outlen, const LWE_PUB *peer_pub_key,
    const LWE_REC *peer_reconciliation, const LWE_PAIR *priv_pub_key,
    uint16_t *w) {
	int ret = -1;
	int has_w = (w != NULL);

	if (!has_w) {
		w = (uint16_t *)malloc(LWE_N_BAR * LWE_N_BAR * sizeof(uint16_t));
	}

	unsigned char *ka = (unsigned char *)malloc((LWE_KEY_BITS >> 3) *
	                    sizeof(unsigned char));

	uint16_t *unpacked_b =
	    (uint16_t *)malloc(LWE_N * LWE_N_BAR * sizeof(uint16_t));

	if (w == NULL || ka == NULL || unpacked_b == NULL) {
		goto err;
	}

	lwe_unpack(unpacked_b, LWE_N * LWE_N_BAR, peer_pub_key->b, LWE_PUB_LENGTH,
	           LWE_LOG2_Q);

#ifdef DEBUG_LOGS
	size_t i;

	debug_printf("  Unpacked B' = ");
	debug_printf("0x%04X 0x%04X 0x%04X 0x%04X ... 0x%04X\n", unpacked_b[0],
	             unpacked_b[1], unpacked_b[2], unpacked_b[3],
	             unpacked_b[LWE_N * LWE_N_BAR - 1]);
#endif

	// W = B'S
	lwe_key_derive_server(w, unpacked_b, priv_pub_key->s);

#ifdef DEBUG_LOGS
	debug_printf("  Computing W = B'S       = ");
	for (i = 0; i < LWE_N_BAR * LWE_N_BAR; i++) {
		debug_printf("0x%04X ", w[i]);
	}
	debug_printf("\n");
#endif

	lwe_reconcile(ka, w, peer_reconciliation->c);

#ifdef DEBUG_LOGS
	debug_printf("  Computing key K = rec(B'S, C) = ");
	for (i = 0; i < (LWE_KEY_BITS >> 3); i++) {
		// debug_printf("0x%02X ", ((unsigned char *)ka)[i]);
		binary_printf(ka[i], 8);
		debug_printf(" ");
	}
	debug_printf("\n");
#endif

	/* no KDF, just copy as much as we can */
	if (outlen > (LWE_KEY_BITS >> 3) * sizeof(unsigned char)) {
		outlen = (LWE_KEY_BITS >> 3) * sizeof(unsigned char);
	}
	memcpy(out, (unsigned char *)ka, outlen);
	ret = outlen;

err:
	if (w && !has_w) {
		bzero(w, LWE_N_BAR * LWE_N_BAR * sizeof(uint16_t));
		free(w);
	}

	if (ka) {
		bzero(ka, (LWE_KEY_BITS >> 3) * sizeof(unsigned char));
		free(ka);
	}

	if (unpacked_b) {
		bzero(unpacked_b, LWE_N_BAR * LWE_N_BAR * sizeof(uint16_t));
		free(unpacked_b);
	}

	return (ret);
}

int LWEKEX_compute_key_bob(void *out, size_t outlen, LWE_REC *reconciliation,
                           const LWE_PUB *peer_pub_key,
                           const LWE_PAIR *priv_pub_key,
                           uint16_t *v) {
	int ret = -1;
	int has_v = (v != NULL);

	if (!has_v) {
		v = (uint16_t *)malloc(LWE_N_BAR * LWE_N_BAR * sizeof(uint16_t));
	}
	unsigned char *kb = (unsigned char *)malloc((LWE_KEY_BITS >> 3) *
	                    sizeof(unsigned char));

	uint16_t *unpacked_b =
	    (uint16_t *)malloc(LWE_N * LWE_N_BAR * sizeof(uint16_t));

	uint16_t *eprimeprime =
	    (uint16_t *)malloc(LWE_N_BAR * LWE_N_BAR * sizeof(uint16_t));

#ifdef DEBUG_LOGS
	size_t i;
	debug_printf("  Sampling Gaussian noise E'' (%i elements) = ",
	             LWE_N_BAR * LWE_N_BAR);  // DEBUG LINE
#endif

	if (v == NULL || kb == NULL || unpacked_b == NULL || eprimeprime == NULL) {
		goto err;
	}

	LWE_SAMPLE_N(eprimeprime, LWE_N_BAR * LWE_N_BAR);

#ifdef DEBUG_LOGS
	debug_printf("%d %d ... %d\n", (int16_t)eprimeprime[0],
	             (int16_t)eprimeprime[1],
	             (int16_t)eprimeprime[LWE_N_BAR * LWE_N_BAR - 1]);
#endif

	lwe_unpack(unpacked_b, LWE_N * LWE_N_BAR, peer_pub_key->b, LWE_PUB_LENGTH,
	           LWE_LOG2_Q);

#ifdef DEBUG_LOGS
	debug_printf("  Unpacked B = ");
	debug_printf("0x%04X 0x%04X 0x%04X 0x%04X ... 0x%04X\n", unpacked_b[0],
	             unpacked_b[1], unpacked_b[2], unpacked_b[3],
	             unpacked_b[LWE_N * LWE_N_BAR - 1]);
	debug_printf("  Computing V = S'B + E'' = ");
#endif

	lwe_key_derive_client(v, unpacked_b, priv_pub_key->s, eprimeprime);

#ifdef DEBUG_LOGS
	for (i = 0; i < LWE_N_BAR * LWE_N_BAR; i++) {
		debug_printf("0x%04X ", v[i]);
	}
	debug_printf("\n");
#endif

#ifdef DEBUG_LOGS
	debug_printf("  Computing reconciliation hint: C = <V>_{2^%d} = ",
	             LWE_LOG2_Q - LWE_EXTRACTED_BITS);
#endif

	lwe_crossround2(reconciliation->c, v);

#ifdef DEBUG_LOGS
	for (i = 0; i < LWE_REC_HINT_LENGTH; i++) {
		binary_printf(reconciliation->c[i], 8);
		debug_printf(" ");
	}
	debug_printf("\n");
#endif

#ifdef DEBUG_LOGS
	debug_printf("  Computing key K = [V]_{2^%d} = ",
	             LWE_LOG2_Q - LWE_EXTRACTED_BITS);  // DEBUG LINE
#endif

	lwe_round2(kb, v);

#ifdef DEBUG_LOGS
	for (i = 0; i < (LWE_KEY_BITS >> 3); i++) {
		// debug_printf("0x%04X ", ((uint32_t *)kb)[i]);
		binary_printf(kb[i], 8);
		debug_printf(" ");
	}
	debug_printf("\n");
#endif

	/* no KDF, just copy as much as we can */
	if (outlen > (LWE_KEY_BITS >> 3) * sizeof(unsigned char)) {
		outlen = (LWE_KEY_BITS >> 3) * sizeof(unsigned char);
	}
	memcpy(out, (unsigned char *)kb, outlen);
	ret = outlen;

err:
	if (v && !has_v) {
		bzero(v, LWE_N_BAR * LWE_N_BAR * sizeof(uint16_t));
		free(v);
	}

	if (kb) {
		bzero(kb, (LWE_KEY_BITS >> 3) * sizeof(unsigned char));
		free(kb);
	}

	if (unpacked_b) {
		bzero(unpacked_b, LWE_N_BAR * LWE_N_BAR * sizeof(uint16_t));
		free(unpacked_b);
	}

	if (eprimeprime) {
		bzero(eprimeprime, LWE_N_BAR * LWE_N_BAR * sizeof(uint16_t));
		free(eprimeprime);
	}

	return (ret);
}
