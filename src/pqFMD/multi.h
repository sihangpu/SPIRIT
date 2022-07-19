#ifndef MULTI_H
#define MULTI_H

#include "params.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

uint64_t inner_prod(const uint16_t vecS[FMD_L],
                const uint64_t vecR[FMD_L]);

void multi_mat_mat(const uint16_t matST[FMD_N * FMD_L],
                   const uint64_t matAT[FMD_L * FMD_L],
                   uint64_t matBT[FMD_N * FMD_L]);

void multi_mat_vec_c2(const uint64_t matBT[FMD_N * FMD_L],
                      const uint16_t vecR[FMD_L],
                      uint64_t vecC[FMD_N]);
                           
void multi_mat_vec_c1(const uint64_t matAT[FMD_L * FMD_L],
                      const uint16_t vecR[FMD_L],
                      uint64_t vecC[FMD_L]);

#endif
