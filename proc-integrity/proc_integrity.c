// SPDX-License-Identifier: GPL-2.0-only
/*
 * Process integrity checker Linux kernel module
 *
 * Copyright (C) 2020 Daniil Kovalev    <dyukovalev@edu.hse.ru>
 * Copyright (C) 2020 Igor Shcherbakov  <ilscherbakov@edu.hse.ru>

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "hash_utils.h"
#include "immediate_action.h"
#include "internal.h"
#include "list_utils.h"
#include "logging.h"

#include <crypto/hash.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/types.h>


/* -------------------------- user-defined options -------------------------- */

#define TIMER_PERIOD (5 * HZ)
#define MONITORED_PIDS_COUNT 2

// NOTE: init process (with PID 1) can NOT be inspected
pid_t MONITORED_PIDS[MONITORED_PIDS_COUNT] =
{
    69,
    70,
};

/* ---------------------- end of user-defined options ----------------------- */


static void
print_memory_sections_table(const struct list_head* memory_sections_list,
                            struct task_struct* task)
{
    struct memory_section* entry = NULL;

    PI_LOG_INFO("\n");
    PI_LOG_INFO("memory sections with VM_WRITE=false for "
                "process with PID %d\n", task->pid);

    PI_LOG_INFO("%16s %16s %16s %64s\n", "from", "to", "flags", "hash");

    list_for_each_entry(entry, memory_sections_list, list)
    {
        int i;
        char hash_buffer[2 * sizeof(entry->digest) + 1];
        hash_buffer[2 * sizeof(entry->digest)] = '\0';
        for (i = 0; i < sizeof(entry->digest); ++i)
            sprintf(hash_buffer + 2 * i, "%02x", entry->digest[i]);

        PI_LOG_INFO("%016lx-%016lx %016lx %s\n",
                    entry->start,
                    entry->end,
                    entry->flags,
                    hash_buffer);
    }

    PI_LOG_INFO("\n");
}

static struct crypto_shash* hash_alg;

static int add_memory_section(struct vm_area_struct* vma,
                              struct task_struct* task,
                              struct list_head* memory_sections_list)
{
    struct memory_section* new_section;
    unsigned long section_len;
    int ret = 0;
    void* memory_ptr;

    if (!vma->vm_file)
        return ret;

    if (vma->vm_flags & VM_WRITE)
        return ret;

    new_section = kmalloc(sizeof(struct memory_section), GFP_KERNEL);
    if (IS_ERR_OR_NULL(new_section))
        return PTR_ERR(new_section);
    list_add_tail(&(new_section->list), memory_sections_list);

    new_section->start = vma->vm_start;
    new_section->end   = vma->vm_end;
    new_section->flags = vma->vm_flags;

    section_len = new_section->end - new_section->start;
    memory_ptr = kmalloc(section_len, GFP_KERNEL);
    if (IS_ERR_OR_NULL(memory_ptr))
    {
        ret = PTR_ERR(memory_ptr);
        goto out;
    }

    ret = access_process_vm(task,
                            new_section->start,
                            memory_ptr,
                            section_len,
                            FOLL_FORCE);

    if (ret != section_len)
    {
        ret = -EPERM;
        goto out_free;
    }

    ret = calc_hash(hash_alg, memory_ptr, section_len, new_section->digest);
    if (ret != 0)
        goto out_free;

out_free:
    kfree(memory_ptr);
out:
    return ret;
}

static int save_memory_sections(struct task_struct* task,
                                struct list_head* memory_sections_list)
{
    int ret;
    struct mm_struct* mm;
    struct vm_area_struct* vma;

    ret = -EACCES;
    if (!ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS))
        goto out;

    ret = -ENOENT;
    mm = get_task_mm(task);
    if (!mm)
        goto out;

    ret = mmap_read_lock_killable(mm);
    if (ret != 0)
    {
        mmput(mm);
        goto out;
    }

    for (vma = mm->mmap; vma; vma = vma->vm_next)
    {
        ret = add_memory_section(vma, task, memory_sections_list);
        if (ret != 0)
            goto out_mm_unlock;
    }

    if (PI_LOG_LEVEL >= PI_LOG_LEVEL_HIGH)
        print_memory_sections_table(memory_sections_list, task);

out_mm_unlock:
    mmap_read_unlock(mm);
    mmput(mm);
out:
    return ret;
}

// list of struct process_info
static struct list_head* monitored_procs_list;

static int add_pid_to_monitored(pid_t pid)
{
    int ret;
    struct process_info* new_proc;

    PI_LOG_INFO_HIGH("add PID %d to monitored\n", pid);

    new_proc = kmalloc(sizeof(struct process_info), GFP_KERNEL);
    if (IS_ERR_OR_NULL(new_proc))
        return PTR_ERR(new_proc);

    new_proc->task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (!new_proc->task)
    {
        PI_LOG_ERR_LOW("cannot find task with PID %d\n", pid);
        return -ENOENT;
    }

    new_proc->sections_list = kmalloc(sizeof(struct memory_section),
                                      GFP_KERNEL);
    if (IS_ERR_OR_NULL(new_proc->sections_list))
        return PTR_ERR(new_proc->sections_list);
    INIT_LIST_HEAD(new_proc->sections_list);

    // will be printed in save_memory_sections
    PI_LOG_INFO_HIGH("initial table for process with PID %d\n", pid);

    // Horrible piece of shit
    // Needed to wait until process mm_struct changes from parent's
    // TODO: find a correct way to wait for this
    msleep(10);

    ret = save_memory_sections(new_proc->task, new_proc->sections_list);
    if (ret != 0)
        return ret;

    list_add_tail(&(new_proc->list), monitored_procs_list);
    return 0;
}


/* --------------------------- _do_fork handlers ---------------------------- */

static int do_fork_entry_handler(struct kretprobe_instance* ri,
                                 struct pt_regs* regs)
{
    return 0;
}
NOKPROBE_SYMBOL(do_fork_entry_handler);

static int do_fork_ret_handler(struct kretprobe_instance* ri,
                               struct pt_regs* regs)
{
    int i;
    unsigned long pid;

    pid = regs_return_value(regs);
    for (i = 0; i < MONITORED_PIDS_COUNT; ++i)
        if (MONITORED_PIDS[i] == pid)
            return add_pid_to_monitored(pid);

    return 0;
}
NOKPROBE_SYMBOL(do_fork_ret_handler);

static struct kretprobe do_fork_kretprobe =
{
    .kp = { .symbol_name = "_do_fork" },
    .handler          = do_fork_ret_handler,
    .entry_handler    = do_fork_entry_handler,
    // Probe up to 1 instance concurrently
    .maxactive        = 1,
};


/* ---------------------------- do_exit handlers ---------------------------- */

static int __kprobes
do_exit_handler_pre(struct kprobe* p, struct pt_regs* regs)
{
    struct process_info* proc_info_entry;

    list_for_each_entry(proc_info_entry, monitored_procs_list, list)
    {
        if (proc_info_entry->task == current)
        {
            PI_LOG_INFO_HIGH("process with PID %d exited\n", current->pid);
            clear_list(proc_info_entry->sections_list);
            list_del((struct list_head*)proc_info_entry);
            kfree(proc_info_entry);
            break;
        }
    }
    return 0;
}

static void __kprobes
do_exit_handler_post(struct kprobe* p,
                     struct pt_regs* regs,
                     unsigned long flags)
{
}

static int do_exit_handler_fault(struct kprobe* p,
                                 struct pt_regs* regs,
                                 int trapnr)
{
    // Return 0 because we don't handle the fault.
    return 0;
}
NOKPROBE_SYMBOL(do_exit_handler_fault);

static struct kprobe do_exit_kprobe =
{
    .symbol_name    = "do_exit",
    .pre_handler    = do_exit_handler_pre,
    .post_handler   = do_exit_handler_post,
    .fault_handler  = do_exit_handler_fault,
};


/* ------------------------------ main section ------------------------------ */

static int inspect_process(struct process_info* proc_info)
{
    int ret;
    struct task_struct* task;
    struct list_head* memory_sections_list;
    bool identical;

    ret = 0;
    task = proc_info->task;

    memory_sections_list = kmalloc(sizeof(struct memory_section), GFP_KERNEL);
    if (IS_ERR_OR_NULL(memory_sections_list))
        return PTR_ERR(memory_sections_list);
    INIT_LIST_HEAD(memory_sections_list);

    ret = save_memory_sections(task, memory_sections_list);
    if (ret != 0)
        return ret;

    BUG_ON(proc_info->sections_list == NULL);
    identical = are_lists_identical(proc_info->sections_list,
                                    memory_sections_list);
    clear_list(memory_sections_list);
    if (!identical)
        return E_HASH_NOT_IDENTICAL;

    return ret;
}

static struct timer_list my_timer;

static void my_timer_callback(struct timer_list* timer)
{
    int ret;
    struct process_info* proc_info_entry;

    list_for_each_entry(proc_info_entry, monitored_procs_list, list)
    {
        ret = inspect_process(proc_info_entry);
        if (ret == E_HASH_NOT_IDENTICAL)
        {
            int imm_ret;
            PI_LOG_ERR_LOW("non-writeable memory section(s) changed in process "
                           "with PID %d\n", proc_info_entry->task->pid);
            imm_ret = immediate_action(proc_info_entry);
            if (imm_ret != 0)
                PI_LOG_ERR_LOW("immediate action returned %d\n", imm_ret);
        }
        else if (ret != 0)
        {
            PI_LOG_ERR_LOW("%d while inspecting PID %d\n",
                           ret, proc_info_entry->task->pid);
        }
        else
        {
            PI_LOG_INFO_MEDIUM("non-writeable memory sections remain the same "
                               "in process with PID %d\n",
                               proc_info_entry->task->pid);
        }
    }

    mod_timer(timer, jiffies + TIMER_PERIOD);
}

static int __init proc_integrity_init(void)
{
    int ret;
    const char* hash_alg_name = "streebog256";

    ret = 0;

    monitored_procs_list = kmalloc(sizeof(struct process_info), GFP_KERNEL);
    if (IS_ERR_OR_NULL(monitored_procs_list))
        return PTR_ERR(monitored_procs_list);
    INIT_LIST_HEAD(monitored_procs_list);

    ret = register_kretprobe(&do_fork_kretprobe);
    if (ret != 0)
    {
        PI_LOG_ERR_LOW("register_kretprobe for _do_fork failed with %d\n", ret);
        return ret;
    }

    ret = register_kprobe(&do_exit_kprobe);
    if (ret != 0)
    {
        PI_LOG_ERR_LOW("register_kprobe for do_exit failed with %d\n", ret);
        return ret;
    }

    hash_alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if (IS_ERR(hash_alg))
    {
        PI_LOG_ERR_LOW("%ld while alloc hash_alg %s\n",
                       PTR_ERR(hash_alg), hash_alg_name);
        return PTR_ERR(hash_alg);
    }

    timer_setup(&my_timer, my_timer_callback, 0);
    mod_timer(&my_timer, jiffies + TIMER_PERIOD);

    return ret;
}

static void __exit proc_integrity_exit(void)
{
    struct process_info* proc_info_entry;

    list_for_each_entry(proc_info_entry, monitored_procs_list, list)
    {
        clear_list(proc_info_entry->sections_list);
    }

    del_timer(&my_timer);
    crypto_free_shash(hash_alg);

    unregister_kprobe(&do_exit_kprobe);
    unregister_kretprobe(&do_fork_kretprobe);

    clear_list(monitored_procs_list);
}

module_init(proc_integrity_init);
module_exit(proc_integrity_exit);

MODULE_LICENSE("GPL v2");
