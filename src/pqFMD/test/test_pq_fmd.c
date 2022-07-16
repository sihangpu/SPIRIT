#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gsl/gsl_sf_bessel.h>

#include "../randombytes.h"
#include "../indcpa.h"

#define NTESTS 1

float t_gen = 0, t_enc = 0, t_dec = 0;
int start, mid1, mid2, end;

int main()
{
    int ErrorOccurred = 0;
    unsigned int i;
    for (i = 0; i < NTESTS; i++)
    {
        double x = 5.0;
        double y = gsl_sf_bessel_J0(x);
        printf("J0(%g) = %.18e\n", x, y);
        return 0;
        t_gen += mid1 - start;
        t_enc += mid2 - mid1;
        t_dec += end - mid2;
    }
    if (!ErrorOccurred)
        printf("\nDecrypted correctly.\n");
    else if (ErrorOccurred == 1)
        printf("\nMismatch messages.\n");

    printf("CIPHERTEXT_BYTES: %d Bytes \n", KYBER_CIPHERBYTES);
    printf("KEYGEN_TIME = %f ms \n", 1000 * (t_gen / NTESTS) / CLOCKS_PER_SEC);
    printf("Enc_TIME = %f ms \n", 1000 * (t_enc / NTESTS) / CLOCKS_PER_SEC);
    printf("Dec_TIME = %f ms \n", 1000 * (t_dec / NTESTS) / CLOCKS_PER_SEC);
    return 0;
}
