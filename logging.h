/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Logging utils for Process integrity checker Linux kernel module
 *
 * Copyright (C) 2020 Daniil Kovalev    <dyukovalev@edu.hse.ru>
 * Copyright (C) 2020 Igor Shcherbakov  <ilscherbakov@edu.hse.ru>

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef PROC_INTEGRITY_LOGGING_H
#define PROC_INTEGRITY_LOGGING_H

#include <linux/printk.h>

// Log verbosity levels

// Notify only when hash changes
#define PI_LOG_LEVEL_LOW    0
// Notify at every hash check (either successful or not)
#define PI_LOG_LEVEL_MEDIUM 1
// Same as PI_LOG_LEVEL_MEDIUM but also print a table of memory sections
#define PI_LOG_LEVEL_HIGH   2

#define PI_LOG_LEVEL PI_LOG_LEVEL_HIGH

// Log macros

#define PI_LOG_PREFIX "PROC_INTEGRITY: "

#define PI_LOG_INFO(...)                                    \
    printk(KERN_INFO PI_LOG_PREFIX "info:  " __VA_ARGS__)   \

#define PI_LOG_ERR(...)                                     \
    printk(KERN_ERR  PI_LOG_PREFIX "error: " __VA_ARGS__)   \

#define PI_LOG_INFO_LOW(...)                                \
    if (PI_LOG_LEVEL >= PI_LOG_LEVEL_LOW)                   \
        PI_LOG_INFO(__VA_ARGS__);                           \

#define PI_LOG_INFO_MEDIUM(...)                             \
    if (PI_LOG_LEVEL >= PI_LOG_LEVEL_MEDIUM)                \
        PI_LOG_INFO(__VA_ARGS__);                           \

#define PI_LOG_INFO_HIGH(...)                               \
    if (PI_LOG_LEVEL >= PI_LOG_LEVEL_HIGH)                  \
        PI_LOG_INFO(__VA_ARGS__);                           \

#define PI_LOG_ERR_LOW(...)                                 \
    if (PI_LOG_LEVEL >= PI_LOG_LEVEL_LOW)                   \
        PI_LOG_ERR(__VA_ARGS__);                            \

#define PI_LOG_ERR_LOW(...)                                 \
    if (PI_LOG_LEVEL >= PI_LOG_LEVEL_LOW)                   \
        PI_LOG_ERR(__VA_ARGS__);                            \

#define PI_LOG_ERR_LOW(...)                                 \
    if (PI_LOG_LEVEL >= PI_LOG_LEVEL_LOW)                   \
        PI_LOG_ERR(__VA_ARGS__);                            \

#endif  // PROC_INTEGRITY_LOGGING_H
