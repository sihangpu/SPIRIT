#ifndef PARAMS_H
#define PARAMS_H


#define FMD_N 20
#define FMD_T 12

#define FMD_L 2304 // 256*9
#define FMD_T_MASK ((1 << FMD_T) - 1) // // modular mask for 2^15: 0x7FFF
#define FMD_ERROR_BOUND (FMD_ETA * FMD_ETA * FMD_L * 2 + FMD_ETA)

#define FMD_ETA 3
#define FMD_EQ 60
#define FMD_Q (((uint64_t)1 << FMD_EQ) - 1) // // modular mask for 2^60: 0x0FFF...FFF

// \lceil FMD_EQ/8 \rceil
#if ((FMD_EQ & 0x07) == 0)
#define FMD_Z_BYTES (FMD_EQ >> 3)
#else
#define FMD_Z_BYTES (1 + ((FMD_EQ - (FMD_EQ & 0x07)) >> 3)) 
#endif

#define FMD_MAT_A_BYTES (FMD_L * FMD_L * 8)
#define FMD_POLYCOINBYTES_ETA_l (FMD_ETA * FMD_L / 4)
#define FMD_POLYCOINBYTES_ETA_n (FMD_ETA * FMD_N / 4)

#define FMD_PK_BYTES (FMD_SEEDBYTES + (FMD_N * FMD_L * FMD_EQ) / 8)
#define FMD_TAG_BYTES ((FMD_L * FMD_EQ + FMD_N + FMD_EQ) / 8)

#define FMD_SEEDBYTES 32
#define FMD_NOISE_SEEDBYTES 32
#define FMD_KEYBYTES 32
#define FMD_HASHBYTES 32

#define FMD_POLYCOINBYTES_ETA1 (FMD_ETA1 * FMD_N / 4)
#define FMD_POLYCOINBYTES_ETA2 (FMD_ETA2 * FMD_N / 4)

#define FMD_POLYBYTES (13 * FMD_N / 8)
#define FMD_POLYVECBYTES (FMD_K * FMD_POLYBYTES)

#endif
