#include "pack_unpack.h"

void BS2MATq(const uint8_t bytes[FMD_MAT_A_BYTES], uint64_t data[FMD_L * FMD_L])
{
	uint16_t i, j;
	uint64_t offset_data, offset_byte;
	for (i = 0; i < FMD_L; ++i)
	{
		offset_data = i * FMD_L;
		for (j = 0; j < FMD_L; ++j)
		{
			offset_byte = ((offset_data  + j) << 3);
			data[offset_data + j] = bytes[offset_byte + 0];
			data[offset_data + j] |= ((bytes[offset_byte + 1] & FMD_Q) << 8);
			data[offset_data + j] |= ((bytes[offset_byte + 2] & FMD_Q) << 16);
			data[offset_data + j] |= ((bytes[offset_byte + 3] & FMD_Q) << 24);
			data[offset_data + j] |= ((bytes[offset_byte + 4] & FMD_Q) << 32);
			data[offset_data + j] |= ((bytes[offset_byte + 5] & FMD_Q) << 40);
			data[offset_data + j] |= ((bytes[offset_byte + 6] & FMD_Q) << 48);
			data[offset_data + j] |= ((bytes[offset_byte + 7] & FMD_Q) << 56);
		}
	}
}

