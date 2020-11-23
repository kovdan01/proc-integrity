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
    int pid;
    struct list_head* sections_list;
};

#endif  // PROC_INTEGRITY_INTERNAL_H
