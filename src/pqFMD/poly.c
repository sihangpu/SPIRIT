#include "poly.h"


void GenMatrix(uint16_t A[KYBER_K][KYBER_K][KYBER_N], const uint8_t seed[KYBER_SEEDBYTES])
{
	uint8_t buf[KYBER_K * KYBER_POLYVECBYTES];
	int i;

	shake128(buf, sizeof(buf), seed, KYBER_SEEDBYTES);

	for (i = 0; i < KYBER_K; i++)
	{
		BS2POLVECq(buf + i * KYBER_POLYVECBYTES, A[i]);
	}
}

void GenBionomialETA1(uint16_t s[KYBER_K][KYBER_N], const uint8_t seed[KYBER_NOISE_SEEDBYTES])
{
	uint8_t buf[KYBER_K * KYBER_POLYCOINBYTES_ETA1];
	size_t i;

	shake128(buf, sizeof(buf), seed, KYBER_NOISE_SEEDBYTES);

	for (i = 0; i < KYBER_K; i++)
	{
		poly_cbd_eta1(s[i], buf + i * KYBER_POLYCOINBYTES_ETA1);
	}
}
void GenBionomialETA2(uint16_t s[KYBER_K][KYBER_N], const uint8_t seed[KYBER_NOISE_SEEDBYTES])
{
	uint8_t buf[KYBER_K * KYBER_POLYCOINBYTES_ETA2];
	size_t i;

	shake128(buf, sizeof(buf), seed, KYBER_NOISE_SEEDBYTES);

	for (i = 0; i < KYBER_K; i++)
	{
		poly_cbd_eta2(s[i], buf + i * KYBER_POLYCOINBYTES_ETA2);
	}
}
