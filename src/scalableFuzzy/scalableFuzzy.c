#include "scalableFuzzy.h"

void server_setup_fuzzy_keypair(uint16_t fpk[KYBER_K][KYBER_N],
								uint8_t seed_A[KYBER_SEEDBYTES],
								uint16_t ftk[KYBER_K][KYBER_N])
{
	indcpa_keypair_fuzzy(fpk, seed_A, ftk);
}

void client_generate_fuzzy_tracking_info(const uint8_t hint[HINT_BYTES],
										 const size_t idx,
										 const uint16_t fpk[KYBER_K][KYBER_N],
										 const uint8_t seed_A[KYBER_SEEDBYTES],
										 uint8_t seed_xy[KYBER_SEEDBYTES],
										 uint16_t ct0[KYBER_K][KYBER_N],
										 uint16_t ct1[KYBER_N])
{
	size_t i;
	uint8_t _temp_msg[KYBER_KEYBYTES] = {0};
	uint8_t _temp_seed_idx[KYBER_SEEDBYTES + IDX_BYTES];
	uint8_t _temp_seed_xy[KYBER_SEEDBYTES];
	uint8_t mask_4_msg, mask_4_hint;
	randombytes(_temp_msg, KYBER_KEYBYTES);
	for (i = 0; i < HINT_BYTES; ++i)
	{
		mask_4_msg = (i == (HINT_BYTES - 1)) ? (0xFF - HINT_BYTE_MASK) : (0x00);
		mask_4_hint = (i == (HINT_BYTES - 1)) ? (HINT_BYTE_MASK) : (0xFF);
		_temp_msg[i] &= mask_4_msg;
		_temp_msg[i] |= (hint[i] & mask_4_hint);
	}
	
	randombytes(seed_xy, KYBER_SEEDBYTES);
	memcpy(_temp_seed_idx, seed_xy, KYBER_SEEDBYTES);

	for (i = 0; i < IDX_BYTES; ++i)
	{
		_temp_seed_idx[i + KYBER_SEEDBYTES] = ((idx >> (i << 3)) & 0xFF);
	}

	shake128(_temp_seed_xy, KYBER_SEEDBYTES, _temp_seed_idx, sizeof(_temp_seed_idx));
	

	indcpa_enc_fuzzy(_temp_msg, fpk, seed_A, _temp_seed_xy, ct0, ct1);
}

void server_expand_fuzzy_list(const uint16_t ftk[KYBER_K][KYBER_N],
							  const uint8_t seed_xy[KYBER_SEEDBYTES],
							  const uint16_t ct0[KYBER_K][KYBER_N],
							  const uint16_t ct1[KYBER_N],
							  uint8_t list[HINT_BYTES * FUZZY_LIST_SIZE])
{
	size_t idx, j;
	uint8_t _temp_seed_idx[KYBER_SEEDBYTES + IDX_BYTES];
	uint8_t _temp_seed_xy[KYBER_SEEDBYTES];
	uint8_t _temp_msg[KYBER_KEYBYTES];
	uint8_t mask_4_hint;
	memcpy(_temp_seed_idx, seed_xy, KYBER_SEEDBYTES);

	for (idx = 0; idx < FUZZY_LIST_SIZE; ++idx)
	{
		for (j = 0; j < IDX_BYTES; ++j)
		{
			_temp_seed_idx[j + KYBER_SEEDBYTES] = ((idx >> (j << 3)) & 0xFF);
		}
		shake128(_temp_seed_xy, KYBER_SEEDBYTES, _temp_seed_idx, sizeof(_temp_seed_idx));

		indcpa_dec_fuzzy(ftk, _temp_seed_xy, ct0, ct1, _temp_msg);

		for (j = 0; j < HINT_BYTES; ++j)
		{
			mask_4_hint = (j == (HINT_BYTES - 1)) ? (HINT_BYTE_MASK) : (0xFF);
			list[j + idx * HINT_BYTES] = (_temp_msg[j] & mask_4_hint);
		}
	}
}
