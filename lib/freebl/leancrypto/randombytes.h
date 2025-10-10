// SPDX-License-Identifier: MIT
// NSS stub for liboqs randombytes.h

#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

// run the random number generator through our mldsa code so we can support
// CKA_SEED (both acquiring it and generating keys from it) and
// DETERMINISTIC signatures (by returning zeros from the RNG)
void mldsa_GetRandomBytes(unsigned char *rdn, int bytes);
#define randombytes mldsa_GetRandomBytes

#endif
