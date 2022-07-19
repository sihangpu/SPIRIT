#ifndef POLY_MUL_H
#define POLY_MUL_H

#include "params.h"
#include <stdint.h>
#include <string.h>
#define SCHB_N 16

#define N_RES (KYBER_N << 1)
#define N_SB (KYBER_N >> 2)
#define N_SB_RES (2*N_SB-1)

#define OVERFLOWING_MUL(X, Y) ((uint16_t)((uint32_t)(X) * (uint32_t)(Y)))

#define KARATSUBA_N 64

void poly_mul_acc(const uint16_t a[KYBER_N], const uint16_t b[KYBER_N], uint16_t res[KYBER_N]);

#endif
