#ifndef PARAMS_H
#define PARAMS_H

#define FMD_L 2304 // 256*9
#define FMD_N 30
#define FMD_T 15
#define FMD_T_MASK ((1 << FMD_T) - 1) // 0x7FFF
#define B (FMD_ETA * FMD_ETA * FMD_L * 2 + FMD_ETA)

#define FMD_ETA 3
#define FMD_EQ 60
#define FMD_Q (((uint64_t)1 << FMD_EQ) - 1) // 0x0FFF...FFF

#define FMD_Z_BYTES (1+ ((FMD_EQ- (FMD_EQ & 0x07))>>3)) // \lceil FMD_EQ/8 \rceil
#define FMD_MAT_A_BYTES (FMD_L * FMD_L * 8)
#define FMD_POLYCOINBYTES_ETA_l (FMD_ETA * FMD_L / 4)
#define FMD_POLYCOINBYTES_ETA_n (FMD_ETA * FMD_N / 4)

#define FMD_TAG_BYTES ((FMD_L * FMD_EQ + FMD_N + FMD_EQ) / 8)


#define KYBER_SEEDBYTES 32
#define KYBER_NOISE_SEEDBYTES 32
#define KYBER_KEYBYTES 32
#define KYBER_HASHBYTES 32

#define KYBER_POLYCOINBYTES_ETA1 (KYBER_ETA1 * KYBER_N / 4)
#define KYBER_POLYCOINBYTES_ETA2 (KYBER_ETA2 * KYBER_N / 4)

#define KYBER_POLYBYTES (13 * KYBER_N / 8)
#define KYBER_POLYVECBYTES (KYBER_K * KYBER_POLYBYTES)

#endif
