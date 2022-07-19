#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../fips202.h"
#include "../randombytes.h"
#include "../pack_unpack.h"
#include "../poly.h"
#include "../indcpa.h"
#include "../multi.h"

#define NTESTS 10

float t_gen = 0, t_enc = 0, t_dec = 0;
int start, mid1, mid2, end;

int main()
{
    int ErrorOccurred = 0;
    unsigned int i;
    uint8_t seed[32];
    uint16_t *matST = calloc(FMD_N * FMD_L, sizeof(uint16_t));
    uint64_t *matBT = calloc(FMD_N * FMD_L, sizeof(uint64_t));
    uint64_t *vecC1 = calloc(FMD_L, sizeof(uint64_t));
    uint64_t *vecC2 = calloc(2, sizeof(uint64_t));

    uint32_t m = 0x0123, m_dec = 0;
    for (i = 0; i < NTESTS; i++)
    {
        memset(matBT, 0, FMD_N * FMD_L * sizeof(uint64_t));
        memset(vecC1, 0, FMD_L * sizeof(uint64_t));
        memset(vecC2, 0, 2 * sizeof(uint64_t));
        m += (uint32_t)(clock());

        start = clock();
        indcpa_keypair_packRegev(matBT, seed, matST);

        mid1 = clock();
        indcpa_enc_packRegev(m, matBT, seed, vecC1, vecC2);

        mid2 = clock();
        m_dec = indcpa_dec_packRegev(matST, vecC1, vecC2);

        end = clock();
        // printf("%x, %x | ", (m & FMD_T_MASK), m_dec);
        if (m_dec != (m & FMD_T_MASK))
            ErrorOccurred = 1;
        t_gen += mid1 - start;
        t_enc += mid2 - mid1;
        t_dec += end - mid2;
    }
    if (!ErrorOccurred)
        printf("\nDecrypted correctly.\n");
    else if (ErrorOccurred == 1)
        printf("\nMismatch messages.\n");

    printf("\nFUZZY_TRACKING_INFO_BYTES: %d Bytes \n", FMD_TAG_BYTES);
    printf("PUBLICKEY_BYTES: %d Bytes \n", FMD_PK_BYTES);
    printf("\nHANDLING 2^{%u} USERS, WITH FALSE_POSITIVE RATE 2^{-%u}\n", FMD_N, FMD_T);
    printf("KEYGEN_TIME = %f ms \n", 1000 * (t_gen / NTESTS) / CLOCKS_PER_SEC);
    printf("USER_FLAG (ENC) _TIME = %f ms \n", 1000 * (t_enc / NTESTS) / CLOCKS_PER_SEC);
    printf("SERVER_DEC_TIME_PER_DETECTION = %f ms \n", 1000 * (t_dec / NTESTS) / CLOCKS_PER_SEC);
    printf("SERVER_COMPUTATION_TIME = %f seconds \n",  (t_dec * (1<<FMD_N) / NTESTS) / CLOCKS_PER_SEC);

    free(matBT);
    free(matST);
    free(vecC1);
    free(vecC2);
    return 0;
}
