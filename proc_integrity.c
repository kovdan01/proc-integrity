#include <crypto/hash.h>
#include <crypto/streebog.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/types.h>

struct memory_section
{
    struct list_head list;

    unsigned long start;
    unsigned long end;
    unsigned long flags;
    unsigned char digest[STREEBOG512_DIGEST_SIZE];
};

static const char* LOG_PREFIX = "PROC_INTEGRITY: ";

struct process_info
{
    int pid;
    struct list_head* sections_list;
};

static struct process_info monitored[] = { {.pid = 1, .sections_list = NULL } };
static size_t monitored_pids_count = 1;

static struct crypto_shash* hash_alg;

static const int E_HASH_NOT_IDENTICAL = 1;

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
        if (memcmp(l->digest, r->digest, STREEBOG512_DIGEST_SIZE) != 0)
            return false;
    }

    if (lhs_pos != lhs || rhs_pos != rhs)
        return false;

    return true;
}

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

static int calc_hash(struct crypto_shash* hash_alg,
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

void print_info(struct list_head* memory_sections_list, int pid)
{
    struct memory_section* entry = NULL;

    printk(KERN_INFO "%sMemory sections with VM_WRITE=false for PID=%d\n", LOG_PREFIX, pid);
    printk(KERN_INFO "%s%16s %16s %16s\n", LOG_PREFIX, "from", "to", "flags");

    list_for_each_entry(entry, memory_sections_list, list)
    {
        printk(KERN_INFO "%s%016lx-%016lx %016lx\n",
               LOG_PREFIX, entry->start, entry->end, entry->flags);
    }

    printk(KERN_INFO "%s\n", LOG_PREFIX);
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

    print_info(memory_sections_list, pid);

    if (monitored[index].sections_list != NULL)
    {
        bool identical = are_lists_identical(monitored[index].sections_list, memory_sections_list);
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
static unsigned long timer_period = 5 * HZ;

void my_timer_callback(struct timer_list* timer)
{
    int ret, i;

    for (i = 0; i < monitored_pids_count; ++i)
    {
        ret = inspect_process(i);
        if (ret == E_HASH_NOT_IDENTICAL)
            printk(KERN_ERR "%sError: non-writeable memory section(s) changed in process with PID %d\n", LOG_PREFIX, monitored[i].pid);
        else if (ret != 0)
            printk(KERN_ERR "%sError %d while inspecting PID %d\n", LOG_PREFIX, ret, monitored[i].pid);
    }

    mod_timer(timer, jiffies + timer_period);
}

static int __init proc_integrity_init(void)
{
    const char* hash_alg_name = "streebog512";
    hash_alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if (IS_ERR(hash_alg))
    {
        printk(KERN_ERR "%sError %ld while alloc hash_alg %s\n", LOG_PREFIX, PTR_ERR(hash_alg), hash_alg_name);
        return PTR_ERR(hash_alg);
    }

    timer_setup(&my_timer, my_timer_callback, 0);
    mod_timer(&my_timer, jiffies + timer_period);

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
