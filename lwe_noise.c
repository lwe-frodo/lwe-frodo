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

/** \file lwe_noise.c
 * Random sampling from the distribution.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include "lwe.h"
#include "lwe_noise.h"

static EVP_CIPHER_CTX *aes_ctx_create() {
	EVP_CIPHER_CTX *aes_ctx = NULL;
	unsigned char aes_key[32];

	if (RAND_bytes(aes_key, sizeof(aes_key)) <= 0) {
		return NULL;
	}

	unsigned char aes_iv[AES_BLOCK_SIZE];
	memset(aes_iv, 0, AES_BLOCK_SIZE);

	aes_ctx = EVP_CIPHER_CTX_new();
	if (aes_ctx == NULL) {
		return NULL;
	}

	if (1 != EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_ctr(), NULL, aes_key, aes_iv)) {
		return NULL;
	}
	return aes_ctx;
}

static void randombuff(EVP_CIPHER_CTX *aes_ctx, unsigned char *buff, int length) {
	memset(buff, 0, length);
	if (1 != EVP_EncryptUpdate(aes_ctx, buff, &length, buff, length)) {
		fprintf(stderr, "EVP error\n");
	}
	if (1 != EVP_EncryptFinal_ex(aes_ctx, buff, &length)) {
		fprintf(stderr, "EVP error\n");
	}
}

/**************************
 * BINOMIAL APPROXIMATION *
 **************************/

uint64_t count_bits8(uint64_t x) {
	// Count bits set in each byte of x using the "SWAR" algorithm.
	x -= (x >> 1) & 0x5555555555555555;
	x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333);
	x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f;
	return x;
}

void lwe_sample_n_binomial24(uint16_t *s, const size_t n) {
	// Fills vector s with n samples from the noise distribution. The noise
	// distribution is shifted binomial B(24, .5) - 12.
	// Runs in constant time. Can be sped up with compiler intrinsics.

	size_t rndlen = 3 * n;  // 24 bits of uniform randomness per output element
	if (rndlen % 8 != 0) {
		rndlen += 8 - (rndlen % 8);    // force rndlen be divisible by 8
	}

	uint64_t *rnd = (uint64_t *)malloc(rndlen);
	if (rnd == NULL) {
		fprintf(stderr, "malloc failure\n");
		return;
	}

	EVP_CIPHER_CTX *aes_ctx = aes_ctx_create();
	randombuff(aes_ctx, (unsigned char *)rnd, rndlen);

	uint64_t *ptr_rnd = rnd;  // processes 3 rnd entries for each 8 output elements

	size_t i, j;
	for (i = 0; i < n; i += 8) {
		uint64_t sum = count_bits8(ptr_rnd[0]) + count_bits8(ptr_rnd[1]) +
		               count_bits8(ptr_rnd[2]);
		// each byte of sum holds the count of the total number of bits set to 1 in
		// the corresponding bytes of rnd[0], rnd[1], rnd[2].

		size_t bound = i + 8 < n ? 8 : n - i;  // min(8, n - i)
		for (j = 0; j < bound; j++) {
			s[i + j] = (uint16_t)((sum >> (j * 8)) & 0xFF) - 12;
		}

		ptr_rnd += 3;
	}
	if (aes_ctx) {
		EVP_CIPHER_CTX_free(aes_ctx);
	}
	bzero(rnd, rndlen);
	free(rnd);
}

uint32_t count_bits32(uint32_t x) {
	/* Count bits set to 1 using the "SWAR" algorithm.
	 * Can be replaced with __builtin_popcount(x) that resolves either to a
	 * a hardware instruction or a library implementation.
	 */
	x -= (x >> 1) & 0x55555555;
	x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
	x = (x + (x >> 4)) & 0x0f0f0f0f;
	x += x >> 8;
	x += x >> 16;
	return x & 0x3F;  // Returned answer is <= 32 which is at most 6 bits long.
}

void lwe_sample_n_binomial32(uint16_t *s, const size_t n) {
	// Fills vector s with n samples from the noise distribution. The noise
	// distribution is shifted binomial B(32, .5) - 16.
	// Runs in constant time. Can be sped up with compiler intrinsics.

	size_t rndlen = 4 * n;  // 32 bits of uniform randomness per output element
	uint32_t *rnd = (uint32_t *)malloc(rndlen);
	if (rnd == NULL) {
		fprintf(stderr, "malloc failure\n");
		return;
	}
	EVP_CIPHER_CTX *aes_ctx = aes_ctx_create();
	randombuff(aes_ctx, (unsigned char *)rnd, rndlen);
	if (aes_ctx) {
		EVP_CIPHER_CTX_free(aes_ctx);
	}
	size_t i;
	for (i = 0; i < n; i++) {
		s[i] = count_bits32(rnd[i]) - 16;
	}
	bzero(rnd, rndlen);
	free(rnd);
}

/***********************************************
 * Inverse transform sampling                  *
 * (I.e., using CDF to sample from a discrete  *
 * probability distribution.)                  *
 ***********************************************/

/* Approximation to the rounded Gaussian with sigma^2 = 1.25. The Renyi
 * divergence of order 25 between the two is ~1.00217.
 * The range of the distribution is [0..3]. Requires 7 bits (plus 1 for the
 * sign).
 */
const size_t CDF_LENGTH_D1 = 4;
const uint8_t CDF_D1[4] = {43, 104, 124, 127}; // out of [0, 127]

/* Approximation to the rounded Gaussian with sigma^2 = 1.00. The Renyi
 * divergence of order 40.0 between the two is 1.000193.
 * The range of the distribution is [0..4]. Requires 11 bits (plus 1 for the
 * sign).
 */
const size_t CDF_LENGTH_D2 = 5;
const uint16_t CDF_D2[5] = {784, 1774, 2022, 2046, 2047}; // out of [0, 2047]

/* Approximation to the rounded Gaussian with sigma^2 = 1.75. The Renyi
 * divergence of order 100 between the two is 1.000301.
 * The range of the distribution is [0..5]. Requires 11 bits (plus 1 for the
 * sign).
 */
const size_t CDF_LENGTH_D3 = 6;
const uint16_t CDF_D3[6] = {602, 1521, 1927, 2031, 2046, 2047}; // out of [0, 2047]

/* Approximation to the rounded Gaussian with sigma^2 = 1.75. The Renyi
 * divergence of order 500 between the two is ~1.0000146.
 * The range of the distribution is [0..6]. Requires 15 bits (plus 1 for the
 * sign).
 */
const size_t CDF_LENGTH_D4 = 7;
const uint16_t CDF_D4[7] = {9651, 24351, 30841, 32500, 32745, 32766, 32767}; // out of [0, 32767]

#if (LWE_CDF_TABLE & 0x0F) != 0
#error "Static constants are not aligned. A potential cache-timing attack."
#endif

typedef struct {
	uint16_t rnd1 : 11;
	uint8_t sign1 : 1;
	uint16_t rnd2 : 11;
	uint8_t sign2 : 1;
} __attribute__((__packed__)) three_bytes_packed;

void lwe_sample_n_inverse_12(uint16_t *s, size_t n) {
	/* Fills vector s with n samples from the noise distribution which requires
	 * 12 bits to sample. The distribution is specified by its CDF. Super-constant
	 * timing: the CDF table is ingested for every sample.
	 */

	OPENSSL_assert(sizeof(three_bytes_packed) ==
	               3);  // should really be a compile-time assert

	size_t rndlen =
	    3 * ((n + 1) / 2);  // 12 bits of unif randomness per output element

	uint8_t *rnd = (uint8_t *)malloc(rndlen);
	if (rnd == NULL) {
		fprintf(stderr, "malloc failure\n");
		return;
	}

	EVP_CIPHER_CTX *aes_ctx = aes_ctx_create();
	randombuff(aes_ctx, (unsigned char *)rnd, rndlen);
	if (aes_ctx) {
		EVP_CIPHER_CTX_free(aes_ctx);
	}

	size_t i;

	for (i = 0; i < n; i += 2) {  // two output elements at a time
		three_bytes_packed *ptr_packed = (three_bytes_packed *)(rnd + 3 * i / 2);

		uint16_t rnd1 = ptr_packed->rnd1;
		uint16_t rnd2 = ptr_packed->rnd2;

		uint8_t sample1 = 0;
		uint8_t sample2 = 0;

		size_t j;
		// No need to compare with the last value.
		for (j = 0; j < LWE_CDF_TABLE_LENGTH - 1; j++) {
			// Constant time comparison: 1 if LWE_CDF_TABLE[j] < rnd1, 0 otherwise.
			// Critically uses the fact that LWE_CDF_TABLE[j] and rnd1 fit in 15 bits.
			sample1 += (uint16_t)(LWE_CDF_TABLE[j] - rnd1) >> 15;
			sample2 += (uint16_t)(LWE_CDF_TABLE[j] - rnd2) >> 15;
		}

		uint8_t sign1 = ptr_packed->sign1;
		uint8_t sign2 = ptr_packed->sign2;

		// Assuming that sign1 is either 0 or 1, flips sample1 iff sign1 = 1
		s[i] = ((-sign1) ^ sample1) + sign1;

		if (i + 1 < n) {
			s[i + 1] = ((-sign2) ^ sample2) + sign2;
		}
	}

	bzero(rnd, rndlen);
	free(rnd);
}

void lwe_sample_n_inverse_16(uint16_t *s, size_t n) {
	/* Fills vector s with n samples from the noise distribution which requires
	 * 16 bits to sample. The distribution is specified by its CDF. Super-constant
	 * timing: the CDF table is ingested for every sample.
	 */

	size_t rndlen = 2 * n;
	uint16_t *rndvec = (uint16_t *)malloc(rndlen);
	if (rndvec == NULL) {
		fprintf(stderr, "malloc failure\n");
		return;
	}

	EVP_CIPHER_CTX *aes_ctx = aes_ctx_create();
	randombuff(aes_ctx, (unsigned char *)rndvec, rndlen);
	if (aes_ctx) {
		EVP_CIPHER_CTX_free(aes_ctx);
	}

	size_t i, j;

	for (i = 0; i < n; ++i) {
		uint8_t sample = 0;
		uint16_t rnd = rndvec[i] >> 1; // drop the least significant bit
		uint8_t sign = rndvec[i] & 0x1; // pick the least significant bit

		// No need to compare with the last value.
		for (j = 0; j < LWE_CDF_TABLE_LENGTH - 1; j++) {
			// Constant time comparison: 1 if LWE_CDF_TABLE[j] < rnd, 0 otherwise.
			// Critically uses the fact that LWE_CDF_TABLE[j] and rnd fit in 15 bits.
			sample += (uint16_t)(LWE_CDF_TABLE[j] - rnd) >> 15;
		}
		// Assuming that sign is either 0 or 1, flips sample iff sign = 1
		s[i] = ((-sign) ^ sample) + sign;
	}

	bzero(rndvec, rndlen);
	free(rndvec);
}

void lwe_sample_n_inverse_8(uint16_t *s, size_t n) {
	/* Fills vector s with n samples from the noise distribution which requires
	 * 8 bits to sample. The distribution is specified by its CDF. Super-constant
	 * timing: the CDF table is ingested for every sample.
	 */

	size_t rndlen = n;
	uint8_t *rndvec = (uint8_t *)malloc(rndlen);
	if (rndvec == NULL) {
		fprintf(stderr, "malloc failure\n");
		return;
	}

	EVP_CIPHER_CTX *aes_ctx = aes_ctx_create();
	randombuff(aes_ctx, (unsigned char *)rndvec, rndlen);
	if (aes_ctx) {
		EVP_CIPHER_CTX_free(aes_ctx);
	}

	size_t i, j;

	for (i = 0; i < n; ++i) {
		uint8_t sample = 0;
		uint8_t rnd = rndvec[i] >> 1; // drop the least significant bit
		uint8_t sign = rndvec[i] & 0x1; // pick the least significant bit

		// No need to compare with the last value.
		for (j = 0; j < LWE_CDF_TABLE_LENGTH - 1; j++) {
			// Constant time comparison: 1 if LWE_CDF_TABLE[j] < rnd, 0 otherwise.
			// Critically uses the fact that LWE_CDF_TABLE[j] and rnd fit in 7 bits.
			sample += (uint8_t)(LWE_CDF_TABLE[j] - rnd) >> 7;
		}
		// Assuming that sign is either 0 or 1, flips sample iff sign = 1
		s[i] = ((-sign) ^ sample) + sign;
	}

	bzero(rndvec, rndlen);
	free(rndvec);
}
