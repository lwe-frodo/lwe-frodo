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

/** \file test.c
 * Basic test program demonstrating LWE-based key exchange.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/rand.h>

static const char rnd_seed[] =
    "string to make the random number generator think it has entropy";

#include "ds_benchmark.h"
#define BENCH_DURATION_SECS 10

#include "lwe.h"
#include "lwe_noise.h"
#include "lwekex.h"

void test_binary_printf(uint64_t n, int bits_num) {
	int i;
	for (i = bits_num - 1; i >= 0; i--) {
		if ((n >> i) & 1) {
			printf("1");
		} else {
			printf("0");
		}

		if (i % 4 == 0) {
			printf(" ");
		}
	}
}

static int test_pack_unpack(uint16_t *in, size_t inlen,
                            unsigned char lsb) {
	int ret = 0;
	size_t i;

	size_t packed_len = LWE_DIV_ROUNDUP(inlen * lsb, 8);
	unsigned char *v_packed = (unsigned char *)malloc(packed_len);
	uint16_t *v_unpacked = (uint16_t *)malloc(inlen * sizeof(uint16_t));

	if (v_packed == NULL || v_unpacked == NULL) {
		fprintf(stderr, "malloc failed\n");
		goto err;
	}

	printf("Packing ");
	for (i = 0; i < inlen; i++) {
		printf("%04X ", in[i]);
	}
	printf("\n");

	lwe_pack(v_packed, packed_len, in, inlen, lsb);

	printf("Packed result ");
	for (i = 0; i < packed_len; i++) {
		printf("%02X ", v_packed[i]);
	}
	printf("\n");

	lwe_unpack(v_unpacked, inlen, v_packed, packed_len, lsb);

	printf("Unpacked result ");
	for (i = 0; i < inlen; i++) {
		printf("%04X ", v_unpacked[i]);
	}
	printf("\n");

	uint16_t mask = (1 << lsb) - 1;

	int match = 1;

	for (i = 0; i < inlen; i++)
		if ((in[i] ^ v_unpacked[i]) & mask) {
			match = 0;
		}
	if (!match) {
		fprintf(stderr, "Pack/unpack failed to match\n");
		goto err;
	}

	ret = 1;
err:

	free(v_packed);
	free(v_unpacked);

	return ret;
}

static int test_packing_unpacking() {
	uint16_t a[3] = {0x1, 0x2, 0x3};

	uint16_t b[4] = {0xFF01, 0xFF02, 0xFF03, 0xFF04};

	uint16_t c[5] = {0x0160, 0x0270, 0x0380, 0x0490, 0x05A0};

	if (!test_pack_unpack(a, 3, 8) || !test_pack_unpack(b, 4, 4) ||
	        !test_pack_unpack(c, 5, 9)) {
		return 0;
	}

	return 1;
}

static int test_sampling() {
	int ret = 0;

	const uint32_t ROUNDS = 1000;

	uint32_t *counts = NULL;
	uint16_t *s = NULL;

	uint16_t max_noise;
	uint64_t cdf_scale;

	max_noise = LWE_CDF_TABLE_LENGTH;
	cdf_scale = LWE_CDF_TABLE[max_noise - 1] + 1;
	printf("Testing the inverse transform method (range = [-%d, %d], "
	       "granularity = %f)\n",
	       max_noise, max_noise, 1. / cdf_scale);

	counts =  // counts for [-max_noise...max_noise - 1]
	    (uint32_t *)malloc(2 * max_noise * sizeof(uint32_t));

	s = (uint16_t *)malloc(LWE_N * LWE_N_BAR * sizeof(uint16_t));

	if ((counts == NULL) || (s == NULL)) {
		goto err;
	}

	memset(counts, 0, sizeof(uint32_t) * 2 * max_noise);

	printf("Sampling from the distribution...\n");
	size_t i, j;
	for (i = 0; i < ROUNDS; i++) {
		LWE_SAMPLE_N(s, LWE_N * LWE_N_BAR);
		for (j = 0; j < LWE_N * LWE_N_BAR; j++) {
			if ((uint16_t)(s[j] + max_noise) >= 2 * max_noise) {
				fprintf(stderr, "Element %hd is out of bounds [-%d, %d]\n", s[j],
				        max_noise, max_noise);
				goto err;
			}
			counts[(uint16_t)(s[j] + max_noise)]++;
		}
	}

	uint64_t total = ROUNDS * LWE_N * LWE_N_BAR;
	double chi_squared = 0;
	int df = 0;  // degrees of freedom

	for (i = 1; i < 2 * max_noise; i++) {
		int v = abs((int) i - max_noise);
		double expect;
		if (v > 0)
			expect = .5 * (double)(LWE_CDF_TABLE[v] - LWE_CDF_TABLE[v - 1]) /
			         cdf_scale * total;
		else {
			expect = (double)(LWE_CDF_TABLE[0] + 1) / cdf_scale * total;
		}

		if (expect == 0) {
			if (counts[i] == 0) {
				continue;
			} else {
				fprintf(stderr,
				        "Element %d of probability 0%% is output by the sampling "
				        "procedure\n",
				        (int) i - max_noise);
				goto err;
			}
		}

		double p = (counts[i] - expect) * (counts[i] - expect) / expect;

		chi_squared += p;
		df++;

		if (counts[i] != 0 || expect != 0)
			printf("count[%4d] = %d, expectation = %.2f\n", (int) i - max_noise,
			       counts[i], expect);
	}

	printf("The chi-squared statistic = %f (df = %d)\n", chi_squared,
	       df);

	double chi_squared_threshold;
	if (df == 7) {
		chi_squared_threshold = 24.322;    // p-value = .999
	} else if (df == 13) {
		chi_squared_threshold = 34.528;    // p-value = .999
	} else {
		chi_squared_threshold = 2 * df;
	}

	if (chi_squared > chi_squared_threshold) {
		printf("Chi-squared test failed.\n");
		//  goto err; // terrible fit! May abort here, but go on with other tests.
	} else {
		printf("Chi-squared test passed.\n");
	}

	ret = 1;

err:
	free(s);
	free(counts);

	return ret;
}

static int bench() {

	int ret = 0;

	LWE_PAIR *alice = NULL;
	LWE_PAIR *bob = NULL;
	LWE_REC *rec = NULL;
	size_t bob_ss_len = LWE_KEY_BITS / 8;
	uint8_t bob_ss[LWE_KEY_BITS / 8];
	uint16_t v[LWE_N_BAR * LWE_N_BAR];
	size_t alice_ss_len = LWE_KEY_BITS / 8;
	uint8_t alice_ss[LWE_KEY_BITS / 8];
	uint16_t w[LWE_N_BAR * LWE_N_BAR];

	alice = LWE_PAIR_new();
	if (alice == NULL) {
		goto err;
	}
	bob = LWE_PAIR_new();
	if (bob == NULL) {
		goto err;
	}
	rec = LWE_REC_new();
	if (rec == NULL) {
		goto err;
	}

	PRINT_BENCHMARK_INSTRUCTIONS

	printf("\n");
	printf("========================================================\n");
	printf("Benchmarking LWE-Frodo-%s\n", LWE_PARAMETERS_NAME);
	printf("========================================================\n");

	PRINT_TIMER_HEADER
	TIME_OPERATION_SECONDS(LWE_PAIR_generate_key(alice, 1, NULL), "Alice key pair generation", BENCH_DURATION_SECS)
	TIME_OPERATION_SECONDS(LWE_PAIR_generate_key(bob, 9, NULL), "Bob key pair generation", BENCH_DURATION_SECS)
	TIME_OPERATION_SECONDS(LWEKEX_compute_key_bob(bob_ss, bob_ss_len, rec, LWE_PAIR_get_publickey(alice), bob, v), "Bob shared secret computation", BENCH_DURATION_SECS)
	TIME_OPERATION_SECONDS(LWEKEX_compute_key_alice(alice_ss, alice_ss_len, LWE_PAIR_get_publickey(bob), rec, alice, w), "Alice shared secret computation", BENCH_DURATION_SECS)
	PRINT_TIMER_FOOTER

	ret = 1;

err:
	LWE_PAIR_free(alice);
	LWE_PAIR_free(bob);

	return ret;

}

static int test_lwekex(int single) {
	LWE_PAIR *alice = NULL, *bob = NULL;
	LWE_REC *rec = NULL;

	LWE_PUB *bob_reconstructed = NULL;
	LWE_REC *rec_reconstructed = NULL;

	unsigned char *apubbuf = NULL, *bpubbuf = NULL;
	size_t apublen, bpublen;

	unsigned char *recbuf = NULL;
	size_t reclen;

	unsigned char *assbuf = NULL, *bssbuf = NULL;
	size_t asslen, bsslen;

	size_t i;
	int ret = 0;
	uint16_t *v =
	    (uint16_t *)malloc(LWE_N_BAR * LWE_N_BAR * sizeof(uint16_t));
	uint16_t *w =
	    (uint16_t *)malloc(LWE_N_BAR * LWE_N_BAR * sizeof(uint16_t));

	alice = LWE_PAIR_new();
	bob = LWE_PAIR_new();
	bob_reconstructed = LWE_PUB_new();
	rec = LWE_REC_new();
	rec_reconstructed = LWE_REC_new();
	if ((alice == NULL) || (bob == NULL) || (bob_reconstructed == NULL) ||
	        (rec == NULL) || (rec_reconstructed == NULL)) {
		goto err;
	}

	if (single) {
		printf("Testing packing/unpacking\n");
		if (!test_packing_unpacking()) {
			goto err;
		}
	}

	if (single) {
		printf("Testing sampling routines\n");
		if (!test_sampling()) {
			goto err;
		}
	}

	if (single) {
		printf("Testing key generation  \n");
	}

	if (single) {
		printf("Generating key for Alice (Server)\n");
	}
	if (!LWE_PAIR_generate_key(alice, 1, NULL)) {
		goto err;
	}
	apublen = i2o_LWE_PUB(LWE_PAIR_get_publickey(alice), &apubbuf);
	if (single) {
		printf("  public B (unpacked, %d bytes) = ", (int)apublen);
	}
	if (apublen <= 0) {
		fprintf(stderr, "Error in LWEKEX routines\n");
		ret = 0;
		goto err;
	}
	if (single) {
		printf("0x%02X 0x%02X 0x%02X 0x%02X ... 0x%02X\n", apubbuf[0],
		       apubbuf[1], apubbuf[3], apubbuf[4], apubbuf[apublen - 1]);
	}

	if (single) {
		printf("Generating key for Bob (Client)\n");
	}
	if (!LWE_PAIR_generate_key(bob, 0, alice->pub->param->seed)) {
		goto err;
	}
	bpublen = i2o_LWE_PUB(LWE_PAIR_get_publickey(bob), &bpubbuf);
	if (single) {
		printf("  public B' (unpacked, %d bytes) = ", (int)bpublen);
		printf("0x%02X 0x%02X 0x%02X 0x%02X ... 0x%02X\n", bpubbuf[0],
		       bpubbuf[1], bpubbuf[3], bpubbuf[4], bpubbuf[apublen - 1]);
	}

	if (single) {
		printf("Testing Bob shared secret generation \n");
	}

	bsslen = 160 / 8;
	bssbuf = (unsigned char *)malloc(bsslen);
	bsslen =
	    LWEKEX_compute_key_bob(bssbuf, bsslen, rec, LWE_PAIR_get_publickey(alice),
	                           bob, v);
	if (single) {
		printf("  key_B (%i bytes) = ", (int)bsslen);
		for (i = 0; i < bsslen; i++) {
			printf("%02X", bssbuf[i]);
		}
		printf("\n");
	}
	reclen = i2o_LWE_REC(rec, &recbuf);
	if (single) {
		printf("  rec (%i bytes) = ", (int)reclen);
		for (i = 0; i < reclen; i++) {
			printf("0x%02X ", ((unsigned char *)recbuf)[i]);
		}
		printf("\n");
	}

	if (single) {
		printf("Reconstructing Bob's values \n");
	}

	// if (single) printf("  Bob's key reconstruction from string \n");
	if (o2i_LWE_PUB(&bob_reconstructed, bpubbuf, bpublen) == NULL) {
		fprintf(stderr,
		        "Error in LWEKEX routines (Bob public key reconstruction)\n");
		ret = 0;
		goto err;
	}
	// if (single) printf("  Bob's reconciliation value reconstruction from
	// string \n");
	if (o2i_LWE_REC(&rec_reconstructed, recbuf, reclen) == NULL) {
		fprintf(stderr,
		        "Error in LWEKEX routines (Bob reconciliation reconstruction)\n");
		ret = 0;
		goto err;
	}

	if (single) {
		printf("Testing Alice shared secret generation \n");
	}

	asslen = 160 / 8;
	assbuf = (unsigned char *)malloc(asslen);
	asslen =
	    LWEKEX_compute_key_alice(assbuf, asslen, bob_reconstructed,
	                             rec_reconstructed, alice, w);
	if (single) {
		printf("  key_A (%i bytes) = ", (int)asslen);
		for (i = 0; i < asslen; i++) {
			printf("%02X", assbuf[i]);
		}
		printf("\n");
	}

	if ((bsslen != asslen) || (memcmp(assbuf, bssbuf, asslen) != 0)) {
		if (single) {
			printf(" failed\n\n");
			fprintf(stderr, "Error in LWEKEX routines (mismatched shared secrets)\n");
		}
		ret = 0;
	} else {
		if (single) {
			printf("ok!\n");
		}
		ret = 1;
	}

	// computing the Hamming distance vector between v and w
	if (single) {
		printf("Hamming distance between the keys: [");
		for (i = 0; i < LWE_N_BAR * LWE_N_BAR; i++) {
			printf("%04X", v[i] ^ w[i]);
			// printf("%04X %04X", v[i], w[i]);
			if (i + 1 < LWE_N_BAR * LWE_N_BAR) {
				printf(", ");
			}
		}
		printf("]\n");

		// computing the number of the lsb bits corrupted by noise

		printf(
		    "The number of corrupted least significant bits (out of %d): [",
		    LWE_LOG2_Q);
		int count_bits = 0;
		int max = 0;
		for (i = 0; i < LWE_N_BAR * LWE_N_BAR; i++) {
			int64_t diff = (int64_t)v[i] - w[i];
			if (diff < 0) {
				diff = -diff;
			}
			count_bits = 0;
			while (diff != 0) {
				count_bits++;
				diff >>= 1;
			}
			if (count_bits > max) {
				max = count_bits;
			}
			printf("%i", count_bits);
			if (i + 1 < LWE_N_BAR * LWE_N_BAR) {
				printf(", ");
			}
		}
		printf("], MAX = %i\n", max);
	}

err:
	free(w);
	free(v);
	free(bssbuf);
	free(assbuf);
	free(apubbuf);
	free(bpubbuf);
	free(recbuf);
	LWE_REC_free(rec_reconstructed);
	LWE_REC_free(rec);
	LWE_PUB_free(bob_reconstructed);
	LWE_PAIR_free(bob);
	LWE_PAIR_free(alice);
	return (ret);
}

int main(int argc, char *argv[]) {
	int ret = 1;

	RAND_seed(rnd_seed, sizeof rnd_seed);

	if (argc == 1) {
		if (!test_lwekex(1)) {
			goto err;
		}
	} else if (argc == 2 && !strcmp((const char *)argv[1], "bench")) {
		if (!bench()) {
			goto err;
		}
	} else if (argc == 2 && !strcmp((const char *)argv[1], "cont")) {
		printf("Running continuous test. ^C to quit.\n\n");
		int iterations = 0;
		int failures = 0;
		time_t starttime = time(NULL);
		while (1) {
			iterations++;
			if (test_lwekex(0) == 1) {
			} else {
				failures++;
			}
			if ((iterations % 100) == 0) {
				printf("Iterations: %d, failures: %d, elapsed time: %ld\n",
				       iterations, failures, time(NULL) - starttime);
				if (iterations > (1 << 20)) {
					break;
				}
			}
		}
	} else if (argc == 2 && !strcmp((const char *)argv[1], "recmy")) {

		// sample random v
		int b = (LWE_LOG2_Q - LWE_EXTRACTED_BITS);
		uint16_t err, v, w;
		int i;

		uint16_t *e, *eprime, *s, *sprime;
		e = (uint16_t *)malloc(LWE_N * sizeof(uint16_t));
		eprime = (uint16_t *)malloc(LWE_N * sizeof(uint16_t));
		s = (uint16_t *)malloc(LWE_N * sizeof(uint16_t));
		sprime = (uint16_t *)malloc(LWE_N * sizeof(uint16_t));

		printf("Running continuous test. ^C to quit.\n\n");
		int iterations = 0;
		int failures = 0;
		while (1) {
			LWE_SAMPLE_N(e, LWE_N);
			LWE_SAMPLE_N(eprime, LWE_N);
			LWE_SAMPLE_N(s, LWE_N);
			LWE_SAMPLE_N(sprime, LWE_N);

			LWE_SAMPLE_N(&err, 1);

			for (i = 0; i < LWE_N; i++) {
				err += e[i] * sprime[i] + eprime[i] * s[i];
			}

			iterations++;
			// generating w and v that are close to each other
			RAND_bytes((unsigned char *)&v, sizeof(uint16_t));
			v &= (1 << LWE_LOG2_Q) - 1;
			w = v + err;
			w &= (1 << LWE_LOG2_Q) - 1;

			uint16_t kb;
			kb = v >> (LWE_LOG2_Q - LWE_EXTRACTED_BITS);
			kb &= ((1 << LWE_EXTRACTED_BITS) - 1);

			uint16_t rec = v >> (LWE_LOG2_Q - LWE_EXTRACTED_BITS - 1) & 1;

			unsigned char ha = (w >> (b - 1)) & 1;
			uint16_t ka = w;
			if (rec != ha) {
				unsigned char hqa = (w >> (b - 2)) & 1;
				uint16_t quarter = (1 << (b - 2));
				ka = (w + hqa * quarter + (1 - hqa) * (-quarter));
			}
			ka >>= (LWE_LOG2_Q - LWE_EXTRACTED_BITS);
			ka &= ((1 << LWE_EXTRACTED_BITS) - 1);
			if (ka != kb) {
				// debug printing bit-by-bit
				printf("\n\nfail #%i out of #%i:\nv - w = ", failures, iterations);
				test_binary_printf(err, 16);
				printf(" |v - w| = ");
				test_binary_printf(err > (1 << LWE_LOG2_Q) ? -err : err, 16);
				printf("\nv = ");
				test_binary_printf(v, 16);
				printf("\nkb = ");
				test_binary_printf(kb, LWE_EXTRACTED_BITS);
				printf("\nrec = ");
				test_binary_printf(rec, 1);
				printf("\nw = ");
				test_binary_printf(w, 16);
				printf("\nka = ");
				test_binary_printf(ka, LWE_EXTRACTED_BITS);

				failures++;
				// getchar();
			}
			if ((iterations % 100000) == 0) {
				printf("Iterations: %d, failures: %d\n",
				       iterations, failures);
				if (iterations > (1 << 30)) {
					break;
				}
			}
		}
		free(e);
		free(eprime);
		free(s);
		free(sprime);
	} else if (argc == 2 && !strcmp((const char *)argv[1], "rec")) {

		// sample random v
		int b = (LWE_LOG2_Q - LWE_EXTRACTED_BITS);
		uint16_t err, v, w;

		uint16_t *e, *eprime, *s, *sprime;
		e = (uint16_t *)malloc(LWE_N * sizeof(uint16_t));
		eprime = (uint16_t *)malloc(LWE_N * sizeof(uint16_t));
		s = (uint16_t *)malloc(LWE_N * sizeof(uint16_t));
		sprime = (uint16_t *)malloc(LWE_N * sizeof(uint16_t));

		printf("Running continuous test. ^C to quit.\n\n");
		int iterations = 0;
		int failures = 0;

		int i;
		while (1) {
			LWE_SAMPLE_N(e, LWE_N);
			LWE_SAMPLE_N(eprime, LWE_N);
			LWE_SAMPLE_N(s, LWE_N);
			LWE_SAMPLE_N(sprime, LWE_N);

			LWE_SAMPLE_N(&err, 1);
			for (i = 0; i < LWE_N; i++) {
				err += e[i] * sprime[i] + eprime[i] * s[i];
			}

			iterations++;
			// generating w and v that are close to each other
			RAND_bytes((unsigned char *)&v, sizeof(uint16_t));
			v &= (1 << LWE_LOG2_Q) - 1;
			w = v + err;
			w &= (1 << LWE_LOG2_Q) - 1;

			uint16_t kb;
			// code from lwe.c->lwe_key_round function
			uint16_t negmask = ~((1 << b) - 1);
			uint16_t half = b > 0 ? 1 << (b - 1) : 0;
			kb = (v + half) & negmask;
			kb >>= LWE_LOG2_Q - LWE_EXTRACTED_BITS;
			kb &= (1 << LWE_EXTRACTED_BITS) - 1;

			unsigned char rec;
			// code from lwe.c->lwe_crossround2
			uint16_t whole2 = 1 << (LWE_LOG2_Q - LWE_EXTRACTED_BITS);
			uint16_t half2 = whole2 >> 1;
			uint16_t mask2 = whole2 - 1;
			uint16_t remainder2 = v & mask2;
			rec = (remainder2 >= half2);

			uint16_t ka;
			//code from lwe.c->lwe_key_round_hints
			uint16_t whole3 = 1 << b;
			uint16_t mask3 = whole3 - 1;
			uint16_t negmask3 = ~mask3;
			uint16_t half3 = 1 << (b - 1);
			uint16_t quarter3 = 1 << (b - 2);

			uint16_t remainder3 = w & mask3;
			uint16_t use_hint = ((remainder3 + quarter3) >> (b - 1)) & 0x1;

			unsigned char h3 = rec;  // the hint
			uint16_t shift3 = use_hint * (2 * h3 - 1) * quarter3;

			// if use_hint = 1 and h = 0, adding -quarter forces rounding down
			//                     h = 1, adding quarter forces rounding up

			ka = (w + half3 + shift3) & negmask3;
			ka >>= LWE_LOG2_Q - LWE_EXTRACTED_BITS;
			ka &= (1 << LWE_EXTRACTED_BITS) - 1;

			if (ka != kb) {
				// debug printing bit-by-bit
				printf("\n\nfail #%i out of #%i:\nv - w = ", failures, iterations);
				test_binary_printf(err, 16);
				printf(" |v - w| = ");
				test_binary_printf(err > (1 << LWE_LOG2_Q) ? -err : err, 16);
				printf("\nv = ");
				test_binary_printf(v, 16);
				printf("\nkb = ");
				test_binary_printf(kb, LWE_EXTRACTED_BITS);
				printf("\nrec = ");
				test_binary_printf(rec, 1);
				printf("\nw = ");
				test_binary_printf(w, 16);
				printf("\nka = ");
				test_binary_printf(ka, LWE_EXTRACTED_BITS);

				failures++;
				// getchar();
			}
			if ((iterations % 100000) == 0) {
				printf("Iterations: %d, failures: %d\n",
				       iterations, failures);
				if (iterations > (1 << 30)) {
					break;
				}
			}
		}
		free(e);
		free(eprime);
		free(s);
		free(sprime);
	} else {
		printf(
		    "Error: argument must be \"cont\" for invoking \
continuously run test.\n");
	}

	ret = 0;

err:
	return (ret);
}
