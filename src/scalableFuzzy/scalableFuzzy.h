#include "randombytes.h"
#include "indcpa.h"

#ifndef USERS_NUM_E
// there are 2^{USERS_NUM_E} users
#define USERS_NUM_E 20
#endif

#if (USERS_NUM_E > 128)
#error "USERS_NUM_E cannot be larger than KYBER_N / 2"
#endif

#ifndef FUZZY_LIST_SIZE_E
// FUZZY_LIST_SIZE = 2^{FUZZY_LIST_SIZE_E}
#define FUZZY_LIST_SIZE_E (USERS_NUM_E >> 1)
#endif

#define FUZZY_LIST_SIZE (1 << FUZZY_LIST_SIZE_E)

// \lceil USERS_NUM_E/8 \rceil
#if ((USERS_NUM_E & 0x07) == 0)
#define HINT_BYTES (USERS_NUM_E >> 3)
#else
#define HINT_BYTES (1 + ((USERS_NUM_E - (USERS_NUM_E & 0x07)) >> 3))
#endif

#if ((FUZZY_LIST_SIZE_E & 0x07) == 0)
#define IDX_BYTES (FUZZY_LIST_SIZE_E >> 3)
#else
#define IDX_BYTES (1 + ((FUZZY_LIST_SIZE_E - (FUZZY_LIST_SIZE_E & 0x07)) >> 3))
#endif

#define HINT_BYTE_MASK ((((size_t)1 << USERS_NUM_E) - 1) >> (USERS_NUM_E - (USERS_NUM_E & 0x07))) // 0x0F for 20-bit hint

void server_setup_fuzzy_keypair(uint16_t fpk[KYBER_K][KYBER_N],
                                uint8_t seed_A[KYBER_SEEDBYTES],
                                uint16_t ftk[KYBER_K][KYBER_N]);

void client_generate_fuzzy_tracking_info(const uint8_t hint[HINT_BYTES],
                                         const size_t idx,
                                         const uint16_t fpk[KYBER_K][KYBER_N],
                                         const uint8_t seed_A[KYBER_SEEDBYTES],
                                         uint8_t seed_xy[KYBER_SEEDBYTES],
                                         uint16_t ct0[KYBER_K][KYBER_N],
                                         uint16_t ct1[KYBER_N]);

void server_expand_fuzzy_list(const uint16_t ftk[KYBER_K][KYBER_N],
                              const uint8_t seed_xy[KYBER_SEEDBYTES],
                              const uint16_t ct0[KYBER_K][KYBER_N],
                              const uint16_t ct1[KYBER_N],
                              uint8_t list[HINT_BYTES * FUZZY_LIST_SIZE]);
