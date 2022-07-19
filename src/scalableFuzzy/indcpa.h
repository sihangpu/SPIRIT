#ifndef INDCPA_H
#define INDCPA_H

#include <string.h>
#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "pack_unpack.h"
#include "poly_mul.h"
#include "fips202.h"

void indcpa_dec_fuzzy(const uint16_t sk[KYBER_K][KYBER_N],
					  const uint8_t seed_xy[KYBER_SEEDBYTES],
					  const uint16_t ct0_in[KYBER_K][KYBER_N],
					  const uint16_t ct1_in[KYBER_N],
					  uint8_t m[KYBER_KEYBYTES]);

void indcpa_enc_fuzzy(const uint8_t m[KYBER_KEYBYTES],
					  const uint16_t pk[KYBER_K][KYBER_N],
					  const uint8_t seed_A[KYBER_SEEDBYTES],
					  const uint8_t seed_xy[KYBER_SEEDBYTES],
					  uint16_t ct0[KYBER_K][KYBER_N],
					  uint16_t ct1[KYBER_N]);

void indcpa_keypair_fuzzy(uint16_t pk[KYBER_K][KYBER_N],
						  uint8_t seed_A[KYBER_SEEDBYTES],
						  uint16_t sk[KYBER_K][KYBER_N]);
#endif
