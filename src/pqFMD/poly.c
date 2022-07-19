#include "poly.h"

void GenBionomialETA_ES(uint16_t s[FMD_N * FMD_L], const uint8_t seed[FMD_NOISE_SEEDBYTES])
{
	uint8_t buf[FMD_N * FMD_POLYCOINBYTES_ETA_l];
	size_t i;

	shake128(buf, sizeof(buf), seed, FMD_NOISE_SEEDBYTES);

	for (i = 0; i < FMD_N; i++)
	{
		poly_cbd_eta_l((s + i * FMD_L), buf + i * FMD_POLYCOINBYTES_ETA_l);
	}
}

void GenBionomialETA_en(uint16_t s[FMD_N], const uint8_t seed[FMD_NOISE_SEEDBYTES])
{
	uint8_t buf[FMD_POLYCOINBYTES_ETA_n];

	shake128(buf, sizeof(buf), seed, FMD_NOISE_SEEDBYTES);
	poly_cbd_eta_n(s, buf);
}

void GenBionomialETA_el(uint16_t s[FMD_L], const uint8_t seed[FMD_NOISE_SEEDBYTES])
{
	uint8_t buf[FMD_POLYCOINBYTES_ETA_l];

	shake128(buf, sizeof(buf), seed, FMD_NOISE_SEEDBYTES);
	poly_cbd_eta_l(s, buf);
}
