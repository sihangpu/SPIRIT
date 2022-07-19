#ifndef PARAMS_H
#define PARAMS_H

#include "config.h"

#define SEEDBYTES 32
#define CRHBYTES 64
#define N 256
#define Q 8380417
#define D 13
#define ROOT_OF_UNITY 1753

#if DILITHIUM_MODE == 2
#define K 4
#define L 4
#define ETA 2
#define TAU 39
#define BETA 156
#define GAMMA1 (1 << 18)
#define GAMMA2 ((Q-1)/44)
#define OMEGA 80

#elif DILITHIUM_MODE == 3
#define K 6
#define L 5
#define ETA 4
#define TAU 49
#define BETA 392 //196*2
#define GAMMA1 (1 << 20)
#define GAMMA2 ((Q-1)/16)
#define OMEGA 55

#elif DILITHIUM_MODE == 5
#define K 8
#define L 7
#define ETA 2
#define TAU 60
#define BETA 240
#define GAMMA1 (1 << 20)
#define GAMMA2 ((Q-1)/16)
#define OMEGA 75

#endif

#define POLYT1_PACKEDBYTES  320
#define POLYT0_PACKEDBYTES  416
#define POLYVECH_PACKEDBYTES (OMEGA + K)

#if GAMMA1 == (1 << 17)
#define POLYZ_PACKEDBYTES   576
#elif GAMMA1 == (1 << 18)
#define POLYZ_PACKEDBYTES   608
#elif GAMMA1 == (1 << 19)
#define POLYZ_PACKEDBYTES   640
#elif GAMMA1 == (1 << 20)
#define POLYZ_PACKEDBYTES   672
#endif

#if GAMMA2 == (Q-1)/88
#define POLYW1_PACKEDBYTES  192
#elif GAMMA2 == (Q-1)/44
#define POLYW1_PACKEDBYTES  160
#elif GAMMA2 == (Q-1)/32
#define POLYW1_PACKEDBYTES  128
#elif GAMMA2 == (Q-1)/16
#define POLYW1_PACKEDBYTES  96
#endif

#if ETA == 2
#define POLYETA_PACKEDBYTES  96
#define POLYETA2_PACKEDBYTES 128
#elif ETA == 4
#define POLYETA_PACKEDBYTES 128
#define POLYETA2_PACKEDBYTES 160
#endif

#define CRYPTO_PUBLICKEYBYTES (SEEDBYTES + K*POLYT1_PACKEDBYTES)
#define CRYPTO_SECRETKEYBYTES (3*SEEDBYTES \
                               + L*POLYETA_PACKEDBYTES \
                               + K*POLYETA_PACKEDBYTES \
                               + K*POLYT0_PACKEDBYTES)
#define CRYPTO2_SECRETKEYBYTES (3*SEEDBYTES \
                               + L*POLYETA2_PACKEDBYTES \
                               + K*POLYETA2_PACKEDBYTES \
                               + K*POLYT0_PACKEDBYTES)
#define CRYPTO_BYTES (SEEDBYTES + L*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)

#endif
