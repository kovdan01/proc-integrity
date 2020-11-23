#ifndef PROC_INTEGRITY_HASH_UTILS_H 
#define PROC_INTEGRITY_HASH_UTILS_H

#include <crypto/hash.h>

int calc_hash(struct crypto_shash* hash_alg,
              const unsigned char* data,
              unsigned int datalen,
              unsigned char* digest);

#endif  // PROC_INTEGRITY_HASH_UTILS_H
