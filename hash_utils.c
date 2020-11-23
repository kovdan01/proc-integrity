// SPDX-License-Identifier: GPL-2.0-only
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

#include "hash_utils.h"

#include <crypto/hash.h>

struct sdesc
{
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc* init_sdesc(struct crypto_shash* hash_alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(hash_alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = hash_alg;
    return sdesc;
}

int calc_hash(struct crypto_shash* hash_alg,
              const unsigned char* data,
              unsigned int datalen,
              unsigned char* digest)
{
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(hash_alg);
    if (IS_ERR(sdesc))
    {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}
