#include "indcpa.h"
#include "randombytes.h"

void indcpa_keypair_fuzzy(uint16_t pk[KYBER_K][KYBER_N],
						  uint8_t seed_A[KYBER_SEEDBYTES],
						  uint16_t sk[KYBER_K][KYBER_N])
{
	uint16_t A[KYBER_K][KYBER_K][KYBER_N];
	uint16_t e[KYBER_K][KYBER_N];

	uint8_t seed_randomcoin[KYBER_NOISE_SEEDBYTES * 2];
	int i, j;

	randombytes(seed_A, KYBER_SEEDBYTES);
	shake128(seed_A, KYBER_SEEDBYTES, seed_A, KYBER_SEEDBYTES); // for not revealing system RNG state
	randombytes(seed_randomcoin, sizeof(seed_randomcoin));

	GenMatrix(A, seed_A);
	GenBionomialETA1(sk, seed_randomcoin);
	GenBionomialETA1(e, seed_randomcoin + KYBER_SEEDBYTES);
	MatrixVectorMul(A, sk, pk, 1);

	for (i = 0; i < KYBER_K; i++)
	{
		for (j = 0; j < KYBER_N; j++)
		{
			pk[i][j] = (pk[i][j] + e[i][j]);
		}
	}
}

void indcpa_enc_fuzzy(const uint8_t m[KYBER_KEYBYTES],
					  const uint16_t pk[KYBER_K][KYBER_N],
					  const uint8_t seed_A[KYBER_SEEDBYTES],
					  const uint8_t seed_xy[KYBER_SEEDBYTES],
					  uint16_t ct0[KYBER_K][KYBER_N],
					  uint16_t ct1[KYBER_N])
{
	int i, j;
	uint16_t A[KYBER_K][KYBER_K][KYBER_N];
	uint16_t e1[KYBER_K][KYBER_N];
	uint16_t r[KYBER_K][KYBER_N];
	uint16_t e2[KYBER_N];

	uint16_t mp[KYBER_N];
	uint16_t mxyp[KYBER_K][KYBER_N];

	uint8_t seed_randomcoin[KYBER_SEEDBYTES * 3];

	randombytes(seed_randomcoin, sizeof(seed_randomcoin));

	uint8_t buf[(KYBER_K)*KYBER_KEYBYTES];
	shake128(buf, sizeof(buf), seed_xy, KYBER_SEEDBYTES);
	for (i = 0; i < KYBER_K; i++)
		BS2POLmsg(buf + i * KYBER_KEYBYTES, mxyp[i]);

	GenMatrix(A, seed_A);
	GenBionomialETA1(r, seed_randomcoin);
	GenBionomialETA2(e1, seed_randomcoin + KYBER_SEEDBYTES);
	MatrixVectorMul(A, r, ct0, 0);

	for (i = 0; i < KYBER_K; i++)
	{
		for (j = 0; j < KYBER_N; j++)
		{
			ct0[i][j] += e1[i][j];
			if (i == 0)
				ct0[i][j] += (mxyp[i][j] << (KYBER_EQ - 1));
			ct0[i][j] &= KYBER_Q;
			ct0[i][j] >>= (KYBER_EQ - KYBER_du); // compress_du
		}
	}

	InnerProd(pk, r, ct1);

	BS2POLmsg(m, mp);
	poly_cbd_eta2(e2, seed_randomcoin + 2 * KYBER_SEEDBYTES);

	for (i = 0; i < KYBER_N; i++)
	{
		ct1[i] += e2[i];
		ct1[i] += (mp[i] << (KYBER_EQ - 1));
		ct1[i] += (mxyp[KYBER_K - 1][i] << (KYBER_EQ - 1));
		ct1[i] &= KYBER_Q;
		ct1[i] >>= (KYBER_EQ - KYBER_dv); // compress_dv
	}
}

void indcpa_dec_fuzzy(const uint16_t sk[KYBER_K][KYBER_N],
					  const uint8_t seed_xy[KYBER_SEEDBYTES],
					  const uint16_t ct0_in[KYBER_K][KYBER_N],
					  const uint16_t ct1_in[KYBER_N],
					  uint8_t m[KYBER_KEYBYTES])
{
	uint16_t ct0[KYBER_K][KYBER_N];
	uint16_t ct1[KYBER_N];
	uint16_t v[KYBER_N] = {0};
	int i, j;
	uint16_t mxyp[KYBER_K][KYBER_N];
	uint8_t buf[(KYBER_K + 1) * KYBER_KEYBYTES];

	for (i = 0; i < KYBER_K; ++i)
	{
		for (j = 0; j < KYBER_N; ++j)
		{
			ct0[i][j] = ct0_in[i][j];
		}
	}
	for (j = 0; j < KYBER_N; ++j)
		ct1[j] = ct1_in[j];

	shake128(buf, sizeof(buf), seed_xy, KYBER_SEEDBYTES);

	for (i = 0; i < KYBER_K; i++)
		BS2POLmsg(buf + i * KYBER_KEYBYTES, mxyp[i]);

	for (i = 0; i < KYBER_K; i++)
	{
		for (j = 0; j < KYBER_N; j++)
		{
			ct0[i][j] <<= (KYBER_EQ - KYBER_du); // decompress_du
			if (i == 0)
				ct0[i][j] -= (mxyp[i][j] << (KYBER_EQ - 1));
			ct0[i][j] &= KYBER_Q;
		}
	}

	InnerProd(ct0, sk, v);

	for (i = 0; i < KYBER_N; i++)
	{
		ct1[i] <<= (KYBER_EQ - KYBER_dv); // decompress_dv
		ct1[i] -= (mxyp[KYBER_K - 1][i] << (KYBER_EQ - 1));
		v[i] -= ct1[i];
		v[i] &= KYBER_Q;
		if (v[i] >> (KYBER_EQ - 1))
			v[i] = KYBER_Q - v[i];
		v[i] >>= (KYBER_EQ - 2);
		v[i] &= 1;
	}

	POLmsg2BS(m, v);
}
