#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../randombytes.h"
#include "../indcpa.h"

#define NTESTS 10000

float t_gen = 0, t_enc = 0, t_dec = 0;
int start, mid1, mid2, end;

static int test_cpa_fuzzy()
{
	uint16_t pk[KYBER_K][KYBER_N] = {0};
	uint8_t seed_A[KYBER_SEEDBYTES];
	uint16_t sk[KYBER_K][KYBER_N];

	uint16_t ct0[KYBER_K][KYBER_N] = {0};
	uint16_t ct1[KYBER_N] = {0};
	uint8_t m[KYBER_SEEDBYTES] = {0}, m_dec[KYBER_SEEDBYTES] = {0};

	uint8_t seed_r[KYBER_SEEDBYTES];

	randombytes(m, KYBER_SEEDBYTES);
	randombytes(seed_r, KYBER_SEEDBYTES);

	// seed_r[0]++;

	start = clock();
	indcpa_keypair_fuzzy(pk, seed_A, sk);
	mid1 = clock();

	indcpa_enc_fuzzy(m, pk, seed_A, seed_r, ct0, ct1);
	mid2 = clock();

	indcpa_dec_fuzzy(sk, seed_r, ct0, ct1, m_dec);
	end = clock();

	if (memcmp(m, m_dec, KYBER_SEEDBYTES))
	{
		// printf("\nERROR: Mismatch messages.\n");
		return 1;
	}

	return 0;
}

int main()
{
	int ErrorOccurred = 0;
	unsigned int i;
	for (i = 0; i < NTESTS; i++)
	{
		ErrorOccurred |= test_cpa_fuzzy();

		t_gen += mid1 - start;
		t_enc += mid2 - mid1;
		t_dec += end - mid2;
	}
	if (!ErrorOccurred)
		printf("\nDecrypted correctly.\n");
	else if(ErrorOccurred == 1)
		printf("\nMismatch messages.\n");

	printf("CIPHERTEXT_BYTES: %d Bytes \n", KYBER_CIPHERBYTES);
	printf("KEYGEN_TIME = %f ms \n", 1000 * (t_gen / NTESTS) / CLOCKS_PER_SEC);
	printf("Enc_TIME = %f ms \n", 1000 * (t_enc / NTESTS) / CLOCKS_PER_SEC);
	printf("Dec_TIME = %f ms \n", 1000 * (t_dec / NTESTS) / CLOCKS_PER_SEC);
	return 0;
}
