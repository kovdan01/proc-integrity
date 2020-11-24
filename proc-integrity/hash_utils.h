/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hash computing utils for Process integrity checker Linux kernel module
 *
 * Copyright (C) 2020 Daniil Kovalev    <dyukovalev@edu.hse.ru>
 * Copyright (C) 2020 Igor Shcherbakov  <ilscherbakov@edu.hse.ru>

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef PROC_INTEGRITY_HASH_UTILS_H
#define PROC_INTEGRITY_HASH_UTILS_H

#include <crypto/hash.h>

int calc_hash(struct crypto_shash* hash_alg,
              const unsigned char* data,
              unsigned int datalen,
              unsigned char* digest);

#endif  // PROC_INTEGRITY_HASH_UTILS_H
