#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"
#include "pack_unpack.h"
#include "fips202.h"
#include "cbd.h"

void GenMatrix(uint16_t a[KYBER_K][KYBER_K][KYBER_N], const uint8_t seed[KYBER_SEEDBYTES]);
void GenBionomialETA2(uint16_t s[KYBER_K][KYBER_N], const uint8_t seed[KYBER_NOISE_SEEDBYTES]);
void GenBionomialETA1(uint16_t s[KYBER_K][KYBER_N], const uint8_t seed[KYBER_NOISE_SEEDBYTES]);

#endif
