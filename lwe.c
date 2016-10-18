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

/** \file lwe.c
 * Core LWE algorithms.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/evp.h>

#include "lwe.h"

#define min(x, y) (((x) < (y)) ? (x) : (y))

// [.]_2
void lwe_round2(unsigned char *out, uint16_t *in) {
	lwe_key_round(in, LWE_N_BAR * LWE_N_BAR, LWE_LOG2_Q - LWE_EXTRACTED_BITS);
	int i;
	for (i = 0; i < LWE_N_BAR * LWE_N_BAR; i++)
		in[i] >>=
		    LWE_LOG2_Q - LWE_EXTRACTED_BITS;  // drop bits that were zeroed out

	// out should have enough space for the key
	lwe_pack(out, LWE_KEY_BITS / 8, in, LWE_N_BAR * LWE_N_BAR,
	         LWE_EXTRACTED_BITS);
}

void lwe_crossround2(unsigned char *out, const uint16_t *in) {
	int i;
	// out should have enough space for N_BAR * N_BAR bits
	memset((unsigned char *)out, 0, LWE_REC_HINT_LENGTH);

	uint16_t whole = 1 << (LWE_LOG2_Q - LWE_EXTRACTED_BITS);
	uint16_t half = whole >> 1;
	uint16_t mask = whole - 1;

	for (i = 0; i < LWE_N_BAR * LWE_N_BAR; i++) {
		uint16_t remainder = in[i] & mask;
		out[i / 8] += (remainder >= half) << (i % 8);
	}
}

void lwe_reconcile(unsigned char *out, uint16_t *w, const unsigned char *hint) {
	lwe_key_round_hints(w, LWE_N_BAR * LWE_N_BAR, LWE_LOG2_Q - LWE_EXTRACTED_BITS,
	                    hint);
	int i;
	for (i = 0; i < LWE_N_BAR * LWE_N_BAR; i++) {
		w[i] >>= LWE_LOG2_Q - LWE_EXTRACTED_BITS;    // drop bits that were zeroed out
	}
	lwe_pack(out, LWE_KEY_BITS / 8, w, LWE_N_BAR * LWE_N_BAR, LWE_EXTRACTED_BITS);
}

/* MATRIX A GENERATION AND MULTIPLICATION ROUTINES.
 *
 * Matrix A is generated on the fly from a seed via a PRNG. The current
 * implementation uses AES128 in the ECB mode keyed with the seed, which must
 * be 16 bytes long. Matrix A is AES128-ECB encryption of a "striped" word
 * matrix B, where B[i,j] = 0 unless j is either 0 or 1 mod 8, when
 * B[i, j] = i if j is divisible by 8, and B[i, j] = j - 1 if j % 8 == 1.
 *                  j'th column
 * i'th row 0 ... 0 i   j 0 ... 0
 *          0 ... 0 i+1 j 0 ... 0
 *          0 ... 0 i+2 j 0 ... 0
 *          0 ... 0 ...
 *          0 ... 0 i+7 j 0 ... 0
 * (i and j are written out in the little-endian order.)
 */

#if LWE_SEED_LENGTH != 16
#error "Seed length must be 16 bytes."
#endif

#if LWE_N % LWE_STRIPE_STEP != 0
#error "Matrix A is not well-defined."
#endif

// Generating A from seed. Seed must be 16 bytes long. If transpose == 1,
// generate A in the transposed order. Output a must have space for
// LWE_N x LWE_N words.
int gen_a(uint16_t *a, const uint8_t *seed, const uint8_t transpose) {
	int i, j;
	int ret = 0;
	/* We generate A using 128 bytes of memory at a time. */
	EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
	if (aes_ctx == NULL) {
		goto err;
	}

	if (1 != EVP_EncryptInit_ex(aes_ctx, EVP_aes_128_ecb(), NULL, seed, NULL)) {
		goto err;
	}

	EVP_CIPHER_CTX_set_padding(aes_ctx, 0);  // no padding in the ECB mode

	size_t a_len = LWE_N * LWE_N * sizeof(uint16_t);

	memset(a, 0, a_len);

	for (i = 0; i < LWE_N; i++)
		for (j = 0; j < LWE_N; j += LWE_STRIPE_STEP) {
			a[i * LWE_N + j] = i;
			a[i * LWE_N + j + 1] = j;
		}

	int outlen;

	if (1 != EVP_EncryptUpdate(aes_ctx, (unsigned char *)a, &outlen,
	                           (unsigned char *)a, a_len) ||
	        ((size_t) outlen != a_len)) {
		goto err;
	}

	if (1 != EVP_EncryptFinal_ex(aes_ctx, (unsigned char *)a, &outlen)) {
		// not necessary since padding is disabled
		goto err;
	}

	if (transpose) // in-situ transpose of the square matrix
		for (i = 0; i < LWE_N; i++)
			for (j = i + 1; j < LWE_N; j++) {
				uint16_t tmp = a[i * LWE_N + j];
				a[i * LWE_N + j] = a[j * LWE_N + i];
				a[j * LWE_N + i] = tmp;
			}

	ret = 1;

err:
	if (aes_ctx != NULL) {
		EVP_CIPHER_CTX_free(aes_ctx);
	}
	return ret;
}

// Generate-and-multiply: generate A row-wise, multiply by s on the right.
int lwe_key_gen_server_gen_a(unsigned char *out,
                             const uint8_t *seed,  // seed for genA
                             const uint16_t *s, const uint16_t *e) {
	// A (N x N)
	// s,e (N x N_BAR)
	// out = A * s + e (N x N_BAR)

	int i, j, k;
	int ret = 0;
	uint16_t *out_unpacked = NULL;
	uint16_t *a_row = NULL;
	uint16_t *s_transpose = NULL;

	EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
	if (aes_ctx == NULL) {
		goto err;
	}

	if (1 != EVP_EncryptInit_ex(aes_ctx, EVP_aes_128_ecb(), NULL, seed, NULL)) {
		goto err;
	}

	EVP_CIPHER_CTX_set_padding(aes_ctx, 0);  // no padding in the ECB mode

	out_unpacked =
	    (uint16_t *)OPENSSL_malloc(LWE_N_BAR * LWE_N * sizeof(int16_t));
	if (out_unpacked == NULL) {
		return 0;
	}

	for (i = 0; i < LWE_N; i++)
		for (j = 0; j < LWE_N_BAR; j++) {
			out_unpacked[i * LWE_N_BAR + j] = e[i * LWE_N_BAR + j];
		}

	size_t a_rowlen = LWE_N * sizeof(int16_t);
	a_row = (uint16_t *)OPENSSL_malloc(a_rowlen);
	if (a_row == NULL) {
		return 0;
	}

	// transpose s to store it in the column-major order
	s_transpose = (uint16_t *)OPENSSL_malloc(LWE_N_BAR * LWE_N * sizeof(int16_t));
	if (s_transpose == NULL) {
		return 0;
	}

	for (j = 0; j < LWE_N; j++)
		for (k = 0; k < LWE_N_BAR; k++) {
			s_transpose[k * LWE_N + j] = s[j * LWE_N_BAR + k];
		}

	for (i = 0; i < LWE_N; i++) {  // go through A's rows
		memset(a_row, 0, a_rowlen);
		for (j = 0; j < LWE_N; j += LWE_STRIPE_STEP) {
			// Loading values in the little-endian order!
			a_row[j] = i;
			a_row[j + 1] = j;
		}

		int outlen;

		if (1 != EVP_EncryptUpdate(aes_ctx, (unsigned char *)a_row, &outlen,
		                           (unsigned char *)a_row, a_rowlen) ||
		        ((size_t) outlen != a_rowlen)) {
			goto err;
		}

		if (1 != EVP_EncryptFinal_ex(aes_ctx, (unsigned char *)a_row, &outlen)) {
			// not necessary since padding is disabled
			goto err;
		}

		for (k = 0; k < LWE_N_BAR; k++) {
			uint16_t sum = 0;
			for (j = 0; j < LWE_N; j++) { // matrix-vector multiplication happens here
				sum += a_row[j] * s_transpose[k * LWE_N + j];
			}
			out_unpacked[i * LWE_N_BAR + k] += sum;
			out_unpacked[i * LWE_N_BAR + k] %= LWE_Q;
		}
	}

	lwe_pack(out, LWE_PUB_LENGTH, out_unpacked, LWE_N * LWE_N_BAR, LWE_LOG2_Q);

	ret = 1;

err:
	if (aes_ctx != NULL) {
		EVP_CIPHER_CTX_free(aes_ctx);
	}

	if (out_unpacked != NULL) {
		OPENSSL_cleanse(out_unpacked, LWE_N_BAR * LWE_N * sizeof(uint16_t));
		OPENSSL_free(out_unpacked);
	}

	if (a_row != NULL) {
		OPENSSL_cleanse(a_row, a_rowlen);
		OPENSSL_free(a_row);
	}

	if (s_transpose != NULL) {
		OPENSSL_cleanse(s_transpose, LWE_N_BAR * LWE_N * sizeof(uint16_t));
		OPENSSL_free(s_transpose);
	}

	return ret;
}

// Generate-then-multiply: Generate A from seed, multiply by s on the right.
// Slower than generating A on the fly. Keeping it for reference purposes.
int __lwe_key_gen_server_gen_a(unsigned char *out,
                               uint8_t *seed,  // seed for gen_a
                               const uint16_t *s, const uint16_t *e) {
	// A (N x N)
	// s,e (N x N_BAR)
	// out = A * s + e (N x N_BAR)

	size_t i, j, k, index = 0;

	uint16_t *s_transpose =
	    (uint16_t *)OPENSSL_malloc(LWE_N_BAR * LWE_N * sizeof(int16_t));
	if (s_transpose == NULL) {
		return 0;
	}

	uint16_t *out_unpacked =
	    (uint16_t *)OPENSSL_malloc(LWE_N_BAR * LWE_N * sizeof(int16_t));
	if (out_unpacked == NULL) {
		return 0;
	}

	for (j = 0; j < LWE_N; j++)
		for (k = 0; k < LWE_N_BAR; k++) {
			s_transpose[k * LWE_N + j] = s[j * LWE_N_BAR + k];
		}

	uint16_t *a = (uint16_t *)OPENSSL_malloc(LWE_N * LWE_N * sizeof(int16_t));
	if (a == NULL) {
		return 0;
	}

	if (!gen_a(a, seed, 0)) {
		return 0;
	}
	// uint16_t *a = lwe_a; // Fixed matrix case. Dimensions must match!

	for (i = 0; i < LWE_N; i++) {
		for (k = 0; k < LWE_N_BAR; k++) {
			uint16_t sum = e[index];
			for (j = 0; j < LWE_N; j++) {
				sum += (uint16_t)a[i * LWE_N + j] * s_transpose[k * LWE_N + j];
			}

			out_unpacked[index] =
			    sum % LWE_Q;  // not really necessary since LWE_Q is a power of 2.
			index++;
		}
	}

	lwe_pack(out, LWE_PUB_LENGTH, out_unpacked, LWE_N * LWE_N_BAR, LWE_LOG2_Q);

	OPENSSL_free(a);

	OPENSSL_cleanse(out_unpacked, LWE_N_BAR * LWE_N * sizeof(uint16_t));
	OPENSSL_free(out_unpacked);

	OPENSSL_cleanse(s_transpose, LWE_N_BAR * LWE_N * sizeof(uint16_t));
	OPENSSL_free(s_transpose);

	return 1;
}

// Generate-and-multiply: generate A column-wise, multiply by s' on the left.
int lwe_key_gen_client_gen_a(unsigned char *out,
                             const uint8_t *seed,  // seed for gen_a
                             const uint16_t *s, const uint16_t *e) {
	// a (N x N)
	// s',e' (N_BAR x N)
	// out = s'a + e' (N_BAR x N)

	int i, j, k, kk;
	int ret = 0;
	uint16_t *out_unpacked = NULL;
	uint16_t *a_cols = NULL;
	uint16_t *a_cols_t = NULL;

	EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
	if (aes_ctx == NULL) {
		goto err;
	}

	if (1 != EVP_EncryptInit_ex(aes_ctx, EVP_aes_128_ecb(), NULL, seed, NULL)) {
		goto err;
	}

	EVP_CIPHER_CTX_set_padding(aes_ctx, 0);  // no padding in the ECB mode

	out_unpacked =
	    (uint16_t *)OPENSSL_malloc(LWE_N_BAR * LWE_N * sizeof(int16_t));
	if (out_unpacked == NULL) {
		return 0;
	}

	for (i = 0; i < LWE_N_BAR; i++)
		for (j = 0; j < LWE_N; j++) {
			out_unpacked[i * LWE_N + j] = e[i * LWE_N + j];
		}

	size_t a_colslen = LWE_N * LWE_STRIPE_STEP * sizeof(int16_t);
	// a_cols stores 8 columns of A at a time.
	a_cols = (uint16_t *)OPENSSL_malloc(a_colslen);
	a_cols_t = (uint16_t *)OPENSSL_malloc(
	               a_colslen);  // a_cols transposed (stored in the column-major order).
	if (a_cols == NULL) {
		return 0;
	}

	for (kk = 0; kk < LWE_N; kk += LWE_STRIPE_STEP) {
		// Go through A's columns, 8 (== LWE_STRIPE_STEP) columns at a time.
		memset(a_cols, 0, a_colslen);
		for (i = 0; i < LWE_N; i++) {
			// Loading values in the little-endian order!
			a_cols[i * LWE_STRIPE_STEP] = i;
			a_cols[i * LWE_STRIPE_STEP + 1] = kk;
		}

		int outlen;

		if (1 != EVP_EncryptUpdate(aes_ctx, (unsigned char *)a_cols, &outlen,
		                           (unsigned char *)a_cols, a_colslen) ||
		        ((size_t) outlen != a_colslen)) {
			goto err;
		}

		if (1 != EVP_EncryptFinal_ex(aes_ctx, (unsigned char *)a_cols, &outlen)) {
			// not necessary since padding is disabled
			goto err;
		}

		// transpose a_cols to have access to it in the column-major order.
		for (i = 0; i < LWE_N; i++)
			for (k = 0; k < LWE_STRIPE_STEP; k++) {
				a_cols_t[k * LWE_N + i] = a_cols[i * LWE_STRIPE_STEP + k];
			}

		for (i = 0; i < LWE_N_BAR; i++)
			for (k = 0; k < LWE_STRIPE_STEP; k++) {
				uint16_t sum = 0;
				for (j = 0; j < LWE_N; j++) {
					sum += s[i * LWE_N + j] * a_cols_t[k * LWE_N + j];
				}
				out_unpacked[i * LWE_N + kk + k] += sum;
				out_unpacked[i * LWE_N + kk + k] %= LWE_Q;
			}
	}

	lwe_pack(out, LWE_PUB_LENGTH, out_unpacked, LWE_N * LWE_N_BAR, LWE_LOG2_Q);

	ret = 1;

err:
	if (aes_ctx != NULL) {
		EVP_CIPHER_CTX_free(aes_ctx);
	}

	if (out_unpacked != NULL) {
		OPENSSL_cleanse(out_unpacked, LWE_N_BAR * LWE_N * sizeof(uint16_t));
		OPENSSL_free(out_unpacked);
	}

	if (a_cols != NULL) {
		OPENSSL_cleanse(a_cols, a_colslen);
		OPENSSL_free(a_cols);
	}

	if (a_cols_t != NULL) {
		OPENSSL_cleanse(a_cols_t, a_colslen);
		OPENSSL_free(a_cols_t);
	}

	return ret;
}

// Generate-then-multiply: Generate A from seed, multiply by s' on the left.
// Slower than generating A on the fly. Keeping it for reference purposes.
int __lwe_key_gen_client_gen_a(unsigned char *out,
                               uint8_t *seed,  // seed for gen_a
                               const uint16_t *s, const uint16_t *e) {
	// a (N x N)
	// s',e' (N_BAR x N)
	// out = s'a + e' (N_BAR x N)

	uint16_t *out_unpacked =
	    (uint16_t *)OPENSSL_malloc(LWE_N_BAR * LWE_N * sizeof(uint16_t));
	if (out_unpacked == NULL) {
		return 0;
	}

	uint16_t *a_transpose =
	    (uint16_t *)OPENSSL_malloc(LWE_N * LWE_N * sizeof(int16_t));
	if (a_transpose == NULL) {
		return 0;
	}

	if (!gen_a(a_transpose, seed, 1)) {
		return 0;
	}
	// uint16_t *a_transpose = lwe_a_transpose; // If the matrix is fixed.

	int i, j, k, index = 0;

	for (k = 0; k < LWE_N_BAR; k++) {
		for (i = 0; i < LWE_N; i++) {
			uint16_t sum = e[index];

			for (j = 0; j < LWE_N; j++) {
				sum += s[k * LWE_N + j] * a_transpose[i * LWE_N + j];
			}

			out_unpacked[index] =
			    sum % LWE_Q;  // not really necessary since LWE_Q is a power of 2.

			index++;
		}
	}

	lwe_pack(out, LWE_PUB_LENGTH, out_unpacked, LWE_N * LWE_N_BAR, LWE_LOG2_Q);

	OPENSSL_free(a_transpose);

	OPENSSL_cleanse(out_unpacked, LWE_N_BAR * LWE_N * sizeof(uint16_t));
	OPENSSL_free(out_unpacked);

	return 1;
}

// multiply by s on the left
void lwe_key_derive_client(uint16_t *out, const uint16_t *b, const uint16_t *s,
                           const uint16_t *e) {
	// b (N x N_BAR)
	// s (N_BAR x N)
	// e (N_BAR x N_BAR)
	// out = sb + e
	int i, j, k;
	for (k = 0; k < LWE_N_BAR; k++) {
		for (i = 0; i < LWE_N_BAR; i++) {
			out[k * LWE_N_BAR + i] = e[k * LWE_N_BAR + i];
			for (j = 0; j < LWE_N; j++) {
				out[k * LWE_N_BAR + i] += s[k * LWE_N + j] * b[j * LWE_N_BAR + i];
			}
			out[k * LWE_N_BAR + i] %=
			    LWE_Q;  // not really necessary since LWE_Q is a power of 2.
		}
	}
}

// multiply by s on the right
void lwe_key_derive_server(uint16_t *out, const uint16_t *b,
                           const uint16_t *s) {
	// b (N_BAR x N)
	// s (N x N_BAR)
	// out = bs
	int i, j, k;
	for (i = 0; i < LWE_N_BAR; i++) {
		for (j = 0; j < LWE_N_BAR; j++) {
			out[i * LWE_N_BAR + j] = 0;
			for (k = 0; k < LWE_N; k++) {
				out[i * LWE_N_BAR + j] += b[i * LWE_N + k] * s[k * LWE_N_BAR + j];
			}
			out[i * LWE_N_BAR + j] %=
			    LWE_Q;  // not really necessary since LWE_Q is a power of 2.
		}
	}
}

// round all elements of a vector to the nearest multiple of 2^b
void lwe_key_round(uint16_t *vec, const size_t length, const int b) {
	size_t i;
	uint16_t negmask = ~((1 << b) - 1);
	uint16_t half = b > 0 ? 1 << (b - 1) : 0;
	for (i = 0; i < length; i++) {
		vec[i] = (vec[i] + half) & negmask;
	}
}

// Round all elements of a vector to the multiple of 2^b, with a hint for the
// direction of rounding when close to the boundary.
void lwe_key_round_hints(uint16_t *vec, const size_t length, const int b,
                         const unsigned char *hint) {
	size_t i;
	uint16_t whole = 1 << b;
	uint16_t mask = whole - 1;
	uint16_t negmask = ~mask;
	uint16_t half = 1 << (b - 1);
	uint16_t quarter = 1 << (b - 2);

	for (i = 0; i < length; i++) {
		uint16_t remainder = vec[i] & mask;
		uint16_t use_hint = ((remainder + quarter) >> (b - 1)) & 0x1;

		unsigned char h = (hint[i / 8] >> (i % 8)) % 2;  // the hint
		uint16_t shift = use_hint * (2 * h - 1) * quarter;

		// if use_hint = 1 and h = 0, adding -quarter forces rounding down
		//                     h = 1, adding quarter forces rounding up

		vec[i] = (vec[i] + half + shift) & negmask;
	}
}

// Pack the input uint16 vector into a char output vector, copying lsb bits
// from each input element. If inlen * lsb / 8 > outlen, only outlen * 8 bits
// are copied.
void lwe_pack(unsigned char *out, const size_t outlen, const uint16_t *in,
              const size_t inlen, const unsigned char lsb) {
	memset((unsigned char *)out, 0, outlen);

	size_t i = 0;            // whole bytes already filled in
	size_t j = 0;            // whole uint16_t already copied
	uint16_t w = 0;          // the leftover, not yet copied
	unsigned char bits = 0;  // the number of lsb in w
	while (i < outlen && (j < inlen || ((j == inlen) && (bits > 0)))) {
		/*
		in: |        |        |********|********|
		                      ^
		                      j
		w : |   ****|
		        ^
		       bits
		out:|**|**|**|**|**|**|**|**|* |
		                            ^^
		                            ib
		*/
		unsigned char b = 0;  // bits in out[i] already filled in
		while (b < 8) {
			int nbits = min(8 - b, bits);
			uint16_t mask = (1 << nbits) - 1;
			unsigned char t =
			    (w >> (bits - nbits)) & mask;  // the bits to copy from w to out
			out[i] = out[i] + (t << (8 - b - nbits));
			b += nbits;
			bits -= nbits;
			w &= ~(mask << bits);  // not strictly necessary; mostly for debugging

			if (bits == 0) {
				if (j < inlen) {
					w = in[j];
					bits = lsb;
					j++;
				} else {
					break;    // the input vector is exhausted
				}
			}
		}
		if (b == 8) {  // out[i] is filled in
			i++;
			b = 0;
		}
	}
}

// Unpack the input char vector into a uint16_t output vector, copying lsb bits
// for each output element from input. outlen must be at least ceil(inlen * 8 /
// lsb).
void lwe_unpack(uint16_t *out, const size_t outlen, const unsigned char *in,
                const size_t inlen, const unsigned char lsb) {
	memset(out, 0, outlen * sizeof(uint16_t));

	size_t i = 0;            // whole uint16_t already filled in
	size_t j = 0;            // whole bytes already copied
	unsigned char w = 0;     // the leftover, not yet copied
	unsigned char bits = 0;  // the number of lsb bits of w
	while (i < outlen && (j < inlen || ((j == inlen) && (bits > 0)))) {
		/*
		in: |  |  |  |  |  |  |**|**|...
		                      ^
		                      j
		w : | *|
		      ^
		      bits
		out:|   *****|   *****|   ***  |        |...
		                      ^   ^
		                      i   b
		*/
		unsigned char b = 0;  // bits in out[i] already filled in
		while (b < lsb) {
			int nbits = min(lsb - b, bits);
			uint16_t mask = (1 << nbits) - 1;
			unsigned char t =
			    (w >> (bits - nbits)) & mask;  // the bits to copy from w to out
			out[i] = out[i] + (t << (lsb - b - nbits));
			b += nbits;
			bits -= nbits;
			w &= ~(mask << bits);  // not strictly necessary; mostly for debugging

			if (bits == 0) {
				if (j < inlen) {
					w = in[j];
					bits = 8;
					j++;
				} else {
					break;    // the input vector is exhausted
				}
			}
		}
		if (b == lsb) {  // out[i] is filled in
			i++;
			b = 0;
		}
	}
}
