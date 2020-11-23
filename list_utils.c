// SPDX-License-Identifier: GPL-2.0-only
/*
 * List manipulation utils for Process integrity checker Linux kernel module
 *
 * Copyright (C) 2020 Daniil Kovalev    <dyukovalev@edu.hse.ru>
 * Copyright (C) 2020 Igor Shcherbakov  <ilscherbakov@edu.hse.ru>

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "list_utils.h"
#include "internal.h"

void clear_list(struct list_head* list)
{
    struct list_head* next = list->next;

    while (next != list)
    {
        list_del(list);
        kfree(list);
        list = next;
        next = list->next;
    }
}

bool are_lists_identical(struct list_head* lhs, struct list_head* rhs)
{
    struct list_head* lhs_pos;
    struct list_head* rhs_pos;

    for (lhs_pos = lhs->next, rhs_pos = rhs->next;
         lhs_pos != lhs && rhs_pos != rhs;
         lhs_pos = lhs_pos->next, rhs_pos = rhs_pos->next)
    {
        struct memory_section* l = (struct memory_section*) lhs_pos;
        struct memory_section* r = (struct memory_section*) rhs_pos;

        if (l->start != r->start)
            return false;
        if (l->end != r->end)
            return false;
        if (l->flags != r->flags)
            return false;
        if (l->start != r->start)
            return false;
        if (memcmp(l->digest, r->digest, sizeof(l->digest)) != 0)
            return false;
    }

    if (lhs_pos != lhs || rhs_pos != rhs)
        return false;

    return true;
}
