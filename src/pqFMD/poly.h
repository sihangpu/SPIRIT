#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"
#include "pack_unpack.h"
#include "fips202.h"
#include "cbd.h"

void GenBionomialETA_en(uint16_t s[FMD_N], const uint8_t seed[FMD_NOISE_SEEDBYTES]);
void GenBionomialETA_el(uint16_t s[FMD_L], const uint8_t seed[FMD_NOISE_SEEDBYTES]);
void GenBionomialETA_ES(uint16_t s[FMD_N * FMD_L], const uint8_t seed[FMD_NOISE_SEEDBYTES]);

#endif
