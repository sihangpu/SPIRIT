#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../randombytes.h"
#include "../scalableFuzzy.h"

#define NTESTS 100

float t_gen = 0, t_enc = 0, t_dec = 0;
int start, mid1, mid2, end;

static int test_scalable_fuzzy()
{
	uint16_t fpk[KYBER_K][KYBER_N] = {0};
	uint8_t seed_A[KYBER_SEEDBYTES];
	uint16_t ftk[KYBER_K][KYBER_N];

	uint16_t ct0[KYBER_K][KYBER_N] = {0};
	uint16_t ct1[KYBER_N] = {0};
	uint8_t seed_r[KYBER_SEEDBYTES];
	uint8_t list[HINT_BYTES * FUZZY_LIST_SIZE];
	uint8_t hint[HINT_BYTES];

	randombytes(hint, HINT_BYTES);
	hint[HINT_BYTES - 1] &= HINT_BYTE_MASK;
	size_t idx = rand() & (FUZZY_LIST_SIZE - 1);

	start = clock();
	server_setup_fuzzy_keypair(fpk, seed_A, ftk);
	mid1 = clock();

	client_generate_fuzzy_tracking_info(hint, idx, fpk, seed_A, seed_r, ct0, ct1);
	mid2 = clock();

	server_expand_fuzzy_list(ftk, seed_r, ct0, ct1, list);
	end = clock();
	if (memcmp(hint, list + idx * HINT_BYTES, HINT_BYTES))
	{
		// printf("\nERROR: Mismatch messages.\n");
		printf("%x, %x\n", hint[0], list[idx * HINT_BYTES]);
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
		ErrorOccurred |= test_scalable_fuzzy();

		t_gen += mid1 - start;
		t_enc += mid2 - mid1;
		t_dec += end - mid2;
	}
	if (!ErrorOccurred)
		printf("\nDecrypted correctly.\n");
	else if (ErrorOccurred == 1)
		printf("\nMismatch messages.\n");

	printf("\nFUZZY_TRACKING_INFO_BYTES: %d Bytes \n", KYBER_CIPHERBYTES);
	printf("FUZZY_PUBLICKEY_BYTES: %d Bytes \n", KYBER_PUBLICKEYBYTES);
	printf("KEYGEN_TIME = %f ms \n", 1000 * (t_gen / NTESTS) / CLOCKS_PER_SEC);
	printf("Enc_TIME = %f ms \n", 1000 * (t_enc / NTESTS) / CLOCKS_PER_SEC);
	printf("Dec_TIME = %f ms \n", 1000 * (t_dec / NTESTS) / CLOCKS_PER_SEC);
	return 0;
}
