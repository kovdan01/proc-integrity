/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Internal definitions for Process integrity checker Linux kernel module
 *
 * Copyright (C) 2020 Daniil Kovalev    <dyukovalev@edu.hse.ru>
 * Copyright (C) 2020 Igor Shcherbakov  <ilscherbakov@edu.hse.ru>

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef PROC_INTEGRITY_INTERNAL_H
#define PROC_INTEGRITY_INTERNAL_H

#include <crypto/streebog.h>
#include <linux/list.h>

#define E_HASH_NOT_IDENTICAL 1

struct memory_section
{
    struct list_head list;

    unsigned long start;
    unsigned long end;
    unsigned long flags;
    unsigned char digest[STREEBOG256_DIGEST_SIZE];
};

struct process_info
{
    struct task_struct* task;
    struct list_head* sections_list;
    bool need_inspection;
};

#endif  // PROC_INTEGRITY_INTERNAL_H
