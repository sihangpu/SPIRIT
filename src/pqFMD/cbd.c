/*---------------------------------------------------------------------
This file has been adapted from the implementation
(available at, Public Domain https://github.com/pq-crystals/kyber)
of "CRYSTALS – Kyber: a CCA-secure module-lattice-based KEM"
by : Joppe Bos, Leo Ducas, Eike Kiltz, Tancrede Lepoint,
Vadim Lyubashevsky, John M. Schanck, Peter Schwabe & Damien stehle
----------------------------------------------------------------------*/

#include "cbd.h"

// static uint64_t load_littleendian(const uint8_t *x, int bytes)
// {
//   int i;
//   uint64_t r = x[0];
//   for (i = 1; i < bytes; i++)
//     r |= (uint64_t)x[i] << (8 * i);
//   return r;
// }

// static uint32_t load32_littleendian(const uint8_t x[4])
// {
//   uint32_t r;
//   r  = (uint32_t)x[0];
//   r |= (uint32_t)x[1] << 8;
//   r |= (uint32_t)x[2] << 16;
//   r |= (uint32_t)x[3] << 24;
//   return r;
// }

static uint32_t load24_littleendian(const uint8_t x[3])
{
  uint32_t r;
  r = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  return r;
}

static void cbd3_l(uint16_t r[FMD_L], const uint8_t buf[3 * FMD_L / 4])
{
  unsigned int i, j;
  uint32_t t, d;
  int16_t a, b;

  for (i = 0; i < FMD_L / 4; i++)
  {
    t = load24_littleendian(buf + 3 * i);
    d = t & 0x00249249;
    d += (t >> 1) & 0x00249249;
    d += (t >> 2) & 0x00249249;

    for (j = 0; j < 4; j++)
    {
      a = (d >> (6 * j + 0)) & 0x7;
      b = (d >> (6 * j + 3)) & 0x7;
      r[4 * i + j] = a - b;
    }
  }
}

static void cbd3_n(uint16_t r[FMD_N], const uint8_t buf[3 * FMD_N / 4])
{
  unsigned int i, j;
  uint32_t t, d;
  int16_t a, b;

  for (i = 0; i < FMD_N / 4; i++)
  {
    t = load24_littleendian(buf + 3 * i);
    d = t & 0x00249249;
    d += (t >> 1) & 0x00249249;
    d += (t >> 2) & 0x00249249;

    for (j = 0; j < 4; j++)
    {
      a = (d >> (6 * j + 0)) & 0x7;
      b = (d >> (6 * j + 3)) & 0x7;
      r[4 * i + j] = a - b;
    }
  }
}


void poly_cbd_eta_l(uint16_t r[FMD_L], const uint8_t buf[FMD_ETA * FMD_L / 4])
{
  cbd3_l(r, buf);
}

void poly_cbd_eta_n(uint16_t r[FMD_N], const uint8_t buf[FMD_ETA * FMD_N / 4])
{
  cbd3_n(r, buf);
}
