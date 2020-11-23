#include "hash_utils.h"
#include "internal.h"
#include "list_utils.h"
#include "logging.h"

#include <crypto/hash.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/types.h>

static struct process_info monitored[] = { {.pid = 1, .sections_list = NULL } };
static size_t monitored_pids_count = 1;

static struct crypto_shash* hash_alg;

void print_info(struct list_head* memory_sections_list, int pid)
{
    struct memory_section* entry = NULL;

    PI_LOG_INFO("\nmemory sections with VM_WRITE=false for PID=%d\n", pid);
    PI_LOG_INFO("%16s %16s %16s %64s\n", "from", "to", "flags", "hash");

    list_for_each_entry(entry, memory_sections_list, list)
    {
        int i;
        char hash_buffer[2 * sizeof(entry->digest) + 1];
        hash_buffer[2 * sizeof(entry->digest)] = '\0';
        for (i = 0; i < sizeof(entry->digest); ++i)
            sprintf(hash_buffer + 2 * i, "%02x", entry->digest[i]);

        PI_LOG_INFO("%016lx-%016lx %016lx %s\n",
                    entry->start, entry->end, entry->flags, hash_buffer);
    }

    PI_LOG_INFO("\n");
}

int add_memory_section(struct vm_area_struct* vma,
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

int inspect_process(int index)
{
    int ret, pid;
    struct vm_area_struct* vma;
    struct task_struct* task;
    struct mm_struct* mm;
    struct list_head* memory_sections_list;

    pid = monitored[index].pid;

    memory_sections_list = kmalloc(sizeof(struct memory_section), GFP_KERNEL);
    if (IS_ERR_OR_NULL(memory_sections_list))
        return PTR_ERR(memory_sections_list);
    INIT_LIST_HEAD(memory_sections_list);

    ret = -ENOENT;
    task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (!task)
        goto out;

    ret = -EACCES;
    if (!ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS))
        goto out_put_task;

    ret = -ENOENT;
    mm = get_task_mm(task);
    if (!mm)
        goto out_put_task;

    ret = mmap_read_lock_killable(mm);
    if (ret != 0)
    {
        mmput(mm);
        goto out_put_task;
    }

    for (vma = mm->mmap; vma; vma = vma->vm_next)
    {
        ret = add_memory_section(vma, task, memory_sections_list);
        if (ret != 0)
            goto out_mm_unlock;
    }

    if (PI_LOG_LEVEL >= PI_LOG_LEVEL_HIGH)
        print_info(memory_sections_list, pid);

    if (monitored[index].sections_list != NULL)
    {
        bool identical = are_lists_identical(monitored[index].sections_list,
                                             memory_sections_list);
        clear_list(memory_sections_list);
        if (!identical)
        {
            ret = E_HASH_NOT_IDENTICAL;
            goto out_mm_unlock;
        }

        if (ret != 0)
            goto out_mm_unlock;
    }
    else
    {
        monitored[index].sections_list = memory_sections_list;
    }

out_mm_unlock:
    mmap_read_unlock(mm);
    mmput(mm);
out_put_task:
    put_task_struct(task);
out:
    return ret;
}

static struct timer_list my_timer;
static const unsigned long TIMER_PERIOD = 5 * HZ;

void my_timer_callback(struct timer_list* timer)
{
    int ret, i;

    for (i = 0; i < monitored_pids_count; ++i)
    {
        ret = inspect_process(i);
        if (ret == E_HASH_NOT_IDENTICAL)
        {
            PI_LOG_ERR_LOW("non-writeable memory section(s) changed in process "
                           "with PID %d\n", monitored[i].pid);
        }
        else if (ret != 0)
        {
            PI_LOG_ERR_LOW("%d while inspecting PID %d\n",
                           ret, monitored[i].pid);
        }
        else
        {
            PI_LOG_INFO_MEDIUM("non-writeable memory sections remain the same "
                               "in process with PID %d\n", monitored[i].pid);
        }
    }

    mod_timer(timer, jiffies + TIMER_PERIOD);
}

static int __init proc_integrity_init(void)
{
    const char* hash_alg_name = "streebog256";
    hash_alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if (IS_ERR(hash_alg))
    {
        PI_LOG_ERR_LOW("%ld while alloc hash_alg %s\n",
                       PTR_ERR(hash_alg), hash_alg_name);
        return PTR_ERR(hash_alg);
    }

    timer_setup(&my_timer, my_timer_callback, 0);
    mod_timer(&my_timer, jiffies + TIMER_PERIOD);

    return 0;
}

static void __exit proc_integrity_exit(void)
{
    int i;

    del_timer(&my_timer);
    crypto_free_shash(hash_alg);

    for (i = 0; i < monitored_pids_count; ++i)
        if (monitored[i].sections_list != NULL)
            clear_list(monitored[i].sections_list);
}

module_init(proc_integrity_init);
module_exit(proc_integrity_exit);

MODULE_LICENSE("GPL");
