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

/** \file lwe.h
 * LWE parameters and function interfaces for core LWE algorithms.
 */

#ifndef HEADER_LWE_H_
#define HEADER_LWE_H_

#include <stdint.h>

// #define DEBUG_LOGS

// #define LWE_PARAMETERS_CHALLENGE
// #define LWE_PARAMETERS_CLASSICAL
#define LWE_PARAMETERS_RECOMMENDED
// #define LWE_PARAMETERS_PARANOID

#ifdef LWE_PARAMETERS_CHALLENGE
#define LWE_LOG2_Q 11  // Log_2 of the modulus Q.
#define LWE_N 352      // Dimensionality of the lattice.
#define LWE_EXTRACTED_BITS 1  // Number of bits extracted from a ring element.
#define LWE_N_BAR 8      // Number of vectors chosen by each of the parties.
#define LWE_KEY_BITS 64  // The length of the reconciled key in bits.
#define LWE_NOISE_D1   // The noise distribution (see lwe_noise.h).
#define LWE_PARAMETERS_NAME "challenge"
#endif

#ifdef LWE_PARAMETERS_CLASSICAL
#define LWE_LOG2_Q 12  // Log_2 of the modulus Q.
#define LWE_N 592      // Dimensionality of the lattice.
#define LWE_EXTRACTED_BITS 2  // Number of bits extracted from a ring element.
#define LWE_N_BAR 8       // Number of vectors chosen by each of the parties.
#define LWE_KEY_BITS 128  // The length of the reconciled key in bits.
#define LWE_NOISE_D2    // The noise distribution (see lwe_noise.h).
#define LWE_PARAMETERS_NAME "classical"
#endif

#ifdef LWE_PARAMETERS_RECOMMENDED
#define LWE_LOG2_Q 15  // Log_2 of the modulus Q.
#define LWE_EXTRACTED_BITS 4  // Number of bits extracted from a ring element.
#define LWE_N 752             // Dimensionality of the lattice.
#define LWE_N_BAR 8       // Number of vectors chosen by each of the parties.
#define LWE_KEY_BITS 256  // The length of the reconciled key in bits.
#define LWE_NOISE_D3    // The noise distribution (see lwe_noise.h).
#define LWE_PARAMETERS_NAME "recommended"
#endif

#ifdef LWE_PARAMETERS_PARANOID
#define LWE_LOG2_Q 15  // Log_2 of the modulus Q.
#define LWE_N 864      // Dimensionality of the lattice.
#define LWE_EXTRACTED_BITS 4  // Number of bits extracted from a ring element.
#define LWE_N_BAR 8       // Number of vectors chosen by each of the parties.
#define LWE_KEY_BITS 256  // The length of the reconciled key in bits.
#define LWE_NOISE_D4   // The noise distribution (see lwe_noise.h).
#define LWE_PARAMETERS_NAME "paranoid"
#endif

#if !defined(LWE_PARAMETERS_CHALLENGE) && !defined(LWE_PARAMETERS_CLASSICAL) && \
    !defined(LWE_PARAMETERS_RECOMMENDED) && !defined(LWE_PARAMETERS_PARANOID)
#error "One parameter set must be selected."
#endif

#define LWE_Q (1 << LWE_LOG2_Q)

#if LWE_LOG2_Q > 16
#error "Modulus Q is too large."
#endif

#if LWE_KEY_BITS > LWE_N_BAR * LWE_N_BAR * LWE_EXTRACTED_BITS
#error "Not enough bits extracted to derive the key"
#endif

#define LWE_SEED_LENGTH 16  // the seed length in bytes

#define LWE_DIV_ROUNDUP(x, y) (((x) + (y)-1) / y)

#define LWE_PUB_LENGTH LWE_DIV_ROUNDUP(LWE_N_BAR *LWE_N *LWE_LOG2_Q, 8)
// Length (in bytes) of the vectors exchanged by parties

#define LWE_REC_HINT_LENGTH LWE_DIV_ROUNDUP(LWE_N_BAR *LWE_N_BAR, 8)
// Length (in bytes) of the reconciliation hint vector

// We generate A is obtained by encrypting a striped matrix (where stripes
// are spaced 8 columns apart) in the AES128-ECB mode.
#define LWE_STRIPE_STEP 8

void lwe_round2_ct(unsigned char *out, uint16_t *in);
void lwe_round2(unsigned char *out, uint16_t *in);

void lwe_crossround2_ct(unsigned char *out, const uint16_t *in);
void lwe_crossround2(unsigned char *out, const uint16_t *in);

void lwe_reconcile_ct(unsigned char *out, uint16_t *w,
                      const unsigned char *hint);
void lwe_reconcile(unsigned char *out, uint16_t *w, const unsigned char *hint);

// generate A on the fly, multiply by s on the right
// computes out = as + e
// where a (N x N), s,e (N x N_BAR),
int lwe_key_gen_server_gen_a(unsigned char *out,
                             const uint8_t *seed,  // seed for gen_a
                             const uint16_t *s, const uint16_t *e);
// Generate-and-multiply: generate A column-wise, multiply by s' on the left.
int lwe_key_gen_client_gen_a(unsigned char *out,
                             const uint8_t *seed,  // seed for gen_a
                             const uint16_t *s, const uint16_t *e);

// multiply by s on the left
// computes out = sb + e
// where b (N x N_BAR), s (N_BAR x N), e (N_BAR x N_BAR)
void lwe_key_derive_client(uint16_t *out, const uint16_t *b, const uint16_t *s,
                           const uint16_t *e);
// multiply by s on the right
void lwe_key_derive_server(uint16_t *out, const uint16_t *b,
                           const uint16_t *s);

// round the entire vector to the nearest multiple of 2^b
void lwe_key_round(uint16_t *vec, const size_t length, const int b);

// round the entire vector to the nearest multiple of 2^b, using the hint vector
// for direction of rounding where necessary
void lwe_key_round_hints(uint16_t *vec, const size_t length, const int b,
                         const unsigned char *hint);

void lwe_pack(unsigned char *out, const size_t outlen, const uint16_t *in,
              const size_t inlen, const unsigned char msb);

void lwe_unpack(uint16_t *out, const size_t outlen, const unsigned char *in,
                const size_t inlen, const unsigned char msb);

#endif /* _LWE_H_ */
