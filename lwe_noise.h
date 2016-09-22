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

/** \file lwe_noise.h
 * Function interfaces for random sampling from the distribution.
 */

#ifndef HEADER_LWE_NOISE_H
#define HEADER_LWE_NOISE_H

#include <stdint.h>

#ifdef LWE_NOISE_D1
#define LWE_SAMPLE_N lwe_sample_n_inverse_8
#define LWE_CDF_TABLE CDF_D1
#define LWE_CDF_TABLE_LENGTH CDF_LENGTH_D1

extern const uint8_t LWE_CDF_TABLE[];
#endif

#ifdef LWE_NOISE_D2
#define LWE_SAMPLE_N lwe_sample_n_inverse_12
#define LWE_CDF_TABLE CDF_D2
#define LWE_CDF_TABLE_LENGTH CDF_LENGTH_D2

extern const uint16_t LWE_CDF_TABLE[];
#endif

#ifdef LWE_NOISE_D3
#define LWE_SAMPLE_N lwe_sample_n_inverse_12
#define LWE_CDF_TABLE CDF_D3
#define LWE_CDF_TABLE_LENGTH CDF_LENGTH_D3

extern const uint16_t LWE_CDF_TABLE[];
#endif

#ifdef LWE_NOISE_D4
#define LWE_SAMPLE_N lwe_sample_n_inverse_16
#define LWE_CDF_TABLE CDF_D4
#define LWE_CDF_TABLE_LENGTH CDF_LENGTH_D4

extern const uint16_t LWE_CDF_TABLE[];
#endif

// Choice of the tables for the table method, also used as the reference CDF by
// lwekextest.

extern const size_t LWE_CDF_TABLE_LENGTH;

void lwe_sample_n_inverse_8(uint16_t *s, const size_t n);
void lwe_sample_n_inverse_12(uint16_t *s, const size_t n);
void lwe_sample_n_inverse_16(uint16_t *s, const size_t n);

#endif
