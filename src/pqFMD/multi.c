#include "multi.h"

uint64_t inner_prod(const uint16_t vecS[FMD_L],
                    const uint64_t vecR[FMD_L])
{
    uint16_t i;
    uint64_t scalar = 0;
    for (i = 0; i < FMD_L; ++i)
    {
        scalar += vecS[i] * vecR[i];
    }
    return scalar;
}
void multi_mat_vec_c1(const uint64_t matAT[FMD_L * FMD_L],
                      const uint16_t vecR[FMD_L],
                      uint64_t vecC[FMD_L])
{
    uint16_t i, k;
    uint64_t offset_row;
    for (i = 0; i < FMD_L; ++i)
    {
        offset_row = i * FMD_L;
        for (k = 0; k < FMD_L; ++k)
        {
            vecC[i] += matAT[offset_row + k] * vecR[k];
        }
    }
}

void multi_mat_vec_c2(const uint64_t matBT[FMD_N * FMD_L],
                      const uint16_t vecR[FMD_L],
                      uint64_t vecC[FMD_N])
{
    uint16_t i, k;
    uint64_t offset_row;
    for (i = 0; i < FMD_N; ++i)
    {
        offset_row = i * FMD_L;
        for (k = 0; k < FMD_L; ++k)
        {
            vecC[i] += matBT[offset_row + k] * vecR[k];
        }
    }
}

void multi_mat_mat(const uint16_t matST[FMD_N * FMD_L],
                   const uint64_t matAT[FMD_L * FMD_L],
                   uint64_t matBT[FMD_N * FMD_L])
{
    uint16_t i, j, k;
    uint64_t offset_s, offset_a;
    for (i = 0; i < FMD_N; ++i)
    {
        offset_s = i * FMD_L;
        for (k = 0; k < FMD_L; ++k)
        {
            offset_a = k * FMD_L;
            for (j = 0; j < FMD_L; ++j)
            {
                matBT[offset_s + j] += matST[offset_s + k] * matAT[offset_a + j];
            }
        }
    }
}
