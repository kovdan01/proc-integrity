/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Immediate actions for Process integrity checker Linux kernel module
 *
 * Copyright (C) 2020 Daniil Kovalev    <dyukovalev@edu.hse.ru>
 * Copyright (C) 2020 Igor Shcherbakov  <ilscherbakov@edu.hse.ru>

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef PROC_INTEGRITY_IMMEDIATE_ACTION_H
#define PROC_INTEGRITY_IMMEDIATE_ACTION_H

#include "internal.h"

#include <linux/sched.h>

// Supported immediate actions

enum
{
    // Do nothing
    PI_IMMEDIATE_ACTION_NONE = 0,
    // Power off
    PI_IMMEDIATE_ACTION_POWEROFF = 1,
    // Send SIGKILL to the process (note that init will not be killed)
    PI_IMMEDIATE_ACTION_KILL = 2,
};

#define PI_IMMEDIATE_ACTION PI_IMMEDIATE_ACTION_POWEROFF

int immediate_action(struct process_info* proc_info);

#endif  // PROC_INTEGRITY_IMMEDIATE_ACTION_H
