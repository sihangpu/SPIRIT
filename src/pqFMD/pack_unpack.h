#ifndef PACK_UNPACK_H
#define PACK_UNPACK_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "params.h"


void BS2MATq(const uint8_t bytes[FMD_MAT_A_BYTES], uint64_t data[FMD_L*FMD_L]);

#endif
