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

/** \file generate_a.c
 * Program to generate a hard-coded "A" matrix.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <openssl/rand.h>

int main(int argc, char *argv[]) {
	char *filename = (argc > 1) ? argv[1] : "lwe_a.h";
	printf("Writing matrix to file %s\n", filename);
	FILE *f = fopen(filename, "wt");
	if (f == NULL) {
		printf("ERROR: Could not open the file");
		return 0;
	}
	int i, j;
	int N = 752;
	uint16_t lwe_a[N * N];
	uint16_t lwe_a_transpose[N * N];

	if (1 != RAND_bytes((unsigned char *)lwe_a, N * N * sizeof(uint16_t)))  {
		printf("ERROR\n");
		exit(1);
	}
	for (i = 0; i < N; i++)
		for (j = 0; j < N; j++) {
			lwe_a_transpose[j * N + i] = lwe_a[i * N + j];
		}

	fprintf(f, "#ifndef _LWE_A_H_\n#define _LWE_A_H_\n\n");
	fprintf(f, "uint16_t lwe_a[%d * %d] = {\n", N, N);

	for (i = 0; i < N * N; i += 8) {
		fprintf(f, "  ");
		for (j = 0; j < 8; j++) {
			fprintf(f, "0x%04X, ", lwe_a[i + j]);
		}
		fprintf(f, "\n");
	}
	fprintf(f, "};\n\n");

	fprintf(f, "uint16_t lwe_a_transpose[%d * %d] = {\n", N, N);

	for (i = 0; i < N * N; i += 8) {
		fprintf(f, "  ");
		for (j = 0; j < 8; j++) {
			fprintf(f, "0x%04X, ", lwe_a_transpose[i + j]);
		}
		fprintf(f, "\n");
	}
	fprintf(f, "};\n#endif /* _LWE_A_H_ */");

	fclose(f);
	return (0);
}
