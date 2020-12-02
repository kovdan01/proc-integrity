// SPDX-License-Identifier: GPL-2.0-only
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

#include "immediate_action.h"
#include "logging.h"

#include <linux/compiler.h>
#include <linux/reboot.h>
#include <linux/sched/signal.h>

int immediate_action(struct process_info* proc_info)
{
    int ret = 0;
    switch (PI_IMMEDIATE_ACTION)
    {
    case PI_IMMEDIATE_ACTION_NONE:
        PI_LOG_INFO_MEDIUM("performing no action");
        break;
        
    case PI_IMMEDIATE_ACTION_POWEROFF:
        PI_LOG_INFO_MEDIUM("powering off");
        kernel_power_off();
        unreachable();
        
    case PI_IMMEDIATE_ACTION_KILL:
        PI_LOG_INFO_MEDIUM("attempting to kill process with PID %d",
                           proc_info->task->pid);
        ret = send_sig(SIGKILL, proc_info->task, 0);
        break;
        
    default:
        PI_LOG_ERR_LOW("unknown action");
        BUG();
        unreachable();
    }
    return ret;
}
