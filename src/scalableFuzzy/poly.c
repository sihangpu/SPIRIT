#include "poly.h"

void MatrixVectorMul(const uint16_t A[KYBER_K][KYBER_K][KYBER_N], const uint16_t s[KYBER_K][KYBER_N], uint16_t res[KYBER_K][KYBER_N], int16_t transpose)
{
	int i, j;
	for (i = 0; i < KYBER_K; i++)
	{
		for (j = 0; j < KYBER_K; j++)
		{
			if (transpose == 1)
			{
				poly_mul_acc(A[j][i], s[j], res[i]);
			}
			else
			{
				poly_mul_acc(A[i][j], s[j], res[i]);
			}	
		}
	}
}

void InnerProd(const uint16_t b[KYBER_K][KYBER_N], const uint16_t s[KYBER_K][KYBER_N], uint16_t res[KYBER_N])
{
	int j;
	for (j = 0; j < KYBER_K; j++)
	{
		poly_mul_acc(b[j], s[j], res);
	}
}

void GenMatrix(uint16_t A[KYBER_K][KYBER_K][KYBER_N], const uint8_t seed[KYBER_SEEDBYTES])
{
	uint8_t buf[KYBER_K * KYBER_POLYVECBYTES];
	int i;

	shake128(buf, sizeof(buf), seed, KYBER_SEEDBYTES);

	for (i = 0; i < KYBER_K; i++)
	{   // Caveat: only for 13-bit coefficients
		BS2POLVECq(buf + i * KYBER_POLYVECBYTES, A[i]);
	}
}

void GenBionomialETA1(uint16_t s[KYBER_K][KYBER_N], const uint8_t seed[KYBER_SEEDBYTES])
{
	uint8_t buf[KYBER_K * KYBER_POLYCOINBYTES_ETA1];
	size_t i;

	shake128(buf, sizeof(buf), seed, KYBER_NOISE_SEEDBYTES);

	for (i = 0; i < KYBER_K; i++)
	{
		poly_cbd_eta1(s[i], buf + i * KYBER_POLYCOINBYTES_ETA1);
	}
}
void GenBionomialETA2(uint16_t s[KYBER_K][KYBER_N], const uint8_t seed[KYBER_SEEDBYTES])
{
	uint8_t buf[KYBER_K * KYBER_POLYCOINBYTES_ETA2];
	size_t i;

	shake128(buf, sizeof(buf), seed, KYBER_NOISE_SEEDBYTES);

	for (i = 0; i < KYBER_K; i++)
	{
		poly_cbd_eta2(s[i], buf + i * KYBER_POLYCOINBYTES_ETA2);
	}
}
