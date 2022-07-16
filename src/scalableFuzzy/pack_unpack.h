#ifndef PACK_UNPACK_H
#define PACK_UNPACK_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "params.h"

void POLVECq2BS(uint8_t bytes[KYBER_POLYVECBYTES], const uint16_t data[KYBER_K][KYBER_N]);
void BS2POLVECq(const uint8_t bytes[KYBER_POLYVECBYTES], uint16_t data[KYBER_K][KYBER_N]);

void BS2POLmsg(const uint8_t bytes[KYBER_KEYBYTES], uint16_t data[KYBER_N]);
void POLmsg2BS(uint8_t bytes[KYBER_KEYBYTES], const uint16_t data[KYBER_N]);

#endif
