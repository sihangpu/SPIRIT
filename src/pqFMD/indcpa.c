#include "indcpa.h"
#include "randombytes.h"
#include "multi.h"

void indcpa_keypair_packRegev(uint64_t pk[FMD_N * FMD_L],
							  uint8_t seed_A[KYBER_SEEDBYTES],
							  uint16_t sk[FMD_N * FMD_L])
{
	uint8_t seed_randomcoin[KYBER_SEEDBYTES * 2];
	int i, j;
	uint64_t offset;

	// allocate temporary memory
	uint8_t *_AT_buf = calloc(FMD_MAT_A_BYTES, sizeof(uint8_t));
	uint64_t *_AT = calloc(FMD_L * FMD_L, sizeof(uint64_t));
	uint16_t *_ET = calloc(FMD_N * FMD_L, sizeof(uint16_t));

	randombytes(seed_A, KYBER_SEEDBYTES);
	shake128(seed_A, KYBER_SEEDBYTES, seed_A, KYBER_SEEDBYTES); // for not revealing system RNG state
	randombytes(seed_randomcoin, sizeof(seed_randomcoin));

	// gen A^t
	shake128(_AT_buf, FMD_MAT_A_BYTES, seed_A, KYBER_SEEDBYTES);
	BS2MATq(_AT_buf, _AT);
	// gen S^t and E^t
	GenBionomialETA_ES(sk, seed_randomcoin);
	GenBionomialETA_ES(_ET, seed_randomcoin + KYBER_SEEDBYTES);
	// S^t * A^t + E^t = B^t + E^t
	multi_mat_mat(sk, _AT, pk);

	for (i = 0; i < FMD_N; i++)
	{
		offset = i * FMD_L;
		for (j = 0; j < FMD_L; j++)
		{
			pk[offset + j] += _ET[offset + j];
		}
	}

	// free mem
	free(_AT_buf);
	free(_AT);
	free(_ET);
}

void indcpa_enc_packRegev(uint32_t m,
						  const uint64_t pk[FMD_N * FMD_L],
						  const uint8_t seed_A[KYBER_SEEDBYTES],
						  uint64_t ct0[FMD_L],
						  uint64_t ct1[2])
{
#if FMD_N > 32
#error "Minimal false-positive rate cannot be smaller than 2^{-32}!"
#endif
	int i;
	uint8_t m_bit;
	uint8_t seed_randomcoin[KYBER_SEEDBYTES * 3];
	uint8_t z_bytes[FMD_Z_BYTES];
	randombytes(seed_randomcoin, sizeof(seed_randomcoin));

	// allocate temporary memory
	uint8_t *_AT_buf = calloc(FMD_MAT_A_BYTES, sizeof(uint8_t));
	uint64_t *_AT = calloc(FMD_L * FMD_L, sizeof(uint64_t));
	uint64_t *_ct1 = calloc(FMD_N, sizeof(uint64_t));
	uint16_t *_r = calloc(FMD_L, sizeof(uint16_t));
	uint16_t *_e1 = calloc(FMD_L, sizeof(uint16_t));
	uint16_t *_e2 = calloc(FMD_N, sizeof(uint16_t));

	// gen A^t, r, e1, e2
	shake128(_AT_buf, FMD_MAT_A_BYTES, seed_A, KYBER_SEEDBYTES);
	BS2MATq(_AT_buf, _AT);
	GenBionomialETA_el(_r, seed_randomcoin);
	GenBionomialETA_el(_e1, seed_randomcoin + KYBER_SEEDBYTES);
	GenBionomialETA_en(_e2, seed_randomcoin + 2*KYBER_SEEDBYTES);
	
	// gen ct0 = A^t * r + e1, ct1 = B^t * r + e2
	multi_mat_vec_c1(_AT, _r, ct0);
	multi_mat_vec_c2(pk, _r, _ct1);
	for (i = 0; i < FMD_L; i++)
	{
		ct0[i] += _e1[i];
		ct0[i] &= FMD_Q;
	}
	for (i = 0; i < FMD_N; i++)
	{
		_ct1[i] += _e2[i];
		m_bit = ((m >> i) & 0x01);
		_ct1[i] += ((m_bit & FMD_Q) << (FMD_EQ - 1));
		_ct1[i] &= FMD_Q;
	}

	// choose z randomly
	randombytes(z_bytes, FMD_Z_BYTES);
	for (i = 0; i < FMD_Z_BYTES; ++i)
	{
		ct1[0] |= (z_bytes[i] & FMD_Q) << (i << 3);
	}
	ct1[0] &= FMD_Q;
	
	// w_i: rouonding z+ct1[i]
	for (i = 0; i < FMD_N; ++i)
	{
		_ct1[i] += ct1[0];
		_ct1[i] &= FMD_Q;
		
		// if (((_ct1[i] >= (FMD_Q >> 2) - B) && (_ct1[i] <= (FMD_Q >> 2) + B)) ||
		// 	((_ct1[i] >= 3 * (FMD_Q >> 2) - B) && (_ct1[i] <= 3 * (FMD_Q >> 2) + B)))
		// {
		// 	printf(" ERROR: z is not in proper range!");
		// }

		// rounding
		if (_ct1[i] >> (FMD_EQ - 1))
			_ct1[i] = FMD_Q - _ct1[i];
		_ct1[i] >>= (FMD_EQ - 2);

		ct1[1] |= ((_ct1[i] & 0x01) << i);
	}

	// free mem
	free(_AT_buf);
	free(_AT);
	free(_ct1);
	free(_r);
	free(_e1);
	free(_e2);
}

uint32_t indcpa_dec_packRegev(const uint16_t sk[FMD_T * FMD_L],
							  const uint64_t ct0[FMD_L],
							  uint64_t ct1[2])
{
#if FMD_T > FMD_N
#error "Requires FMD_T <= FMD_N!"
#endif
	uint32_t m = 0;
	uint64_t v[FMD_T] = {0};
	int i;
	for (i = 0; i < FMD_T; ++i)
	{
		v[i] = inner_prod((sk + i * FMD_L), ct0);
		v[i] += ct1[0];
		v[i] &= FMD_Q;
		if (v[i] >> (FMD_EQ - 1))
			v[i] = FMD_Q - v[i];
		v[i] >>= (FMD_EQ - 2);
		m |= ((v[i] & 0x01) << i);
	}
	m ^= ct1[1];
	m &= FMD_T_MASK;
	return m;
}
