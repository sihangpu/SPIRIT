/*---------------------------------------------------------------------
This file has been adapted from the implementation 
(available at, Public Domain https://github.com/pq-crystals/kyber) 
of "CRYSTALS – Kyber: a CCA-secure module-lattice-based KEM"
by : Joppe Bos, Leo Ducas, Eike Kiltz, Tancrede Lepoint, 
Vadim Lyubashevsky, John M. Schanck, Peter Schwabe & Damien stehle
----------------------------------------------------------------------*/
#ifndef CBD_H
#define CBD_H

#include <stdint.h>
#include "params.h"

void poly_cbd_eta_l(uint16_t r[FMD_L], const uint8_t buf[FMD_ETA*FMD_L/4]);
void poly_cbd_eta_n(uint16_t r[FMD_N], const uint8_t buf[FMD_ETA*FMD_N/4]);
#endif
