#ifndef INDCPA_H
#define INDCPA_H

#include <string.h>
#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "pack_unpack.h"
#include "randombytes.h"
#include "multi.h"
#include "fips202.h"

uint32_t indcpa_dec_packRegev(const uint16_t sk[FMD_T * FMD_L],
							  const uint64_t ct0[FMD_L],
							  uint64_t ct1[2]);

void indcpa_enc_packRegev(uint32_t m,
						  const uint64_t pk[FMD_N * FMD_L],
						  const uint8_t seed_A[FMD_SEEDBYTES],
						  uint64_t ct0[FMD_L],
						  uint64_t ct1[2]);

void indcpa_keypair_packRegev(uint64_t pk[FMD_N * FMD_L],
							  uint8_t seed_A[FMD_SEEDBYTES],
							  uint16_t sk[FMD_N * FMD_L]);
#endif
