#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/types.h>

static const char* LOG_PREFIX = "PROC_INTEGRITY: ";

static int monitored_pids[] = { 1 };
static size_t monitored_pids_count = 1;

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

struct memory_section 
{
    struct list_head list;
    
    unsigned long start;
    unsigned long end;
    unsigned long flags;
};

void print_info(struct list_head* memory_sections_list, int pid)
{
    struct memory_section* entry = NULL;
    
    printk(KERN_INFO "%sAll memory sections for PID=%d\n", LOG_PREFIX, pid);
    printk(KERN_INFO "%s%16s %16s %16s\n", LOG_PREFIX, "from", "to", "flags");

    list_for_each_entry(entry, memory_sections_list, list)
    {
        printk(KERN_INFO "%s%016lx-%016lx %016lx\n", LOG_PREFIX, entry->start, entry->end, entry->flags);
    }
    
    printk(KERN_INFO "%s\n", LOG_PREFIX);
    printk(KERN_INFO "%sMemory sections with VM_WRITE=false for PID=%d\n", LOG_PREFIX, pid);
    printk(KERN_INFO "%s%16s %16s %16s\n", LOG_PREFIX, "from", "to", "flags");

    list_for_each_entry(entry, memory_sections_list, list)
    {
        if (!(entry->flags & VM_WRITE))
            printk(KERN_INFO "%s%016lx-%016lx %016lx\n", LOG_PREFIX, entry->start, entry->end, entry->flags);
    }
    
    printk(KERN_INFO "%s\n", LOG_PREFIX);
}

int add_memory_section(struct vm_area_struct* vma, struct task_struct* task, struct list_head* memory_sections_list)
{   
    struct memory_section* new_section;
    unsigned long section_len;
    int bytes_count;
    void* memory_ptr;
    
    if (!vma->vm_file)
        return 0;

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
        return PTR_ERR(memory_ptr);

    bytes_count = access_process_vm(task, new_section->start, memory_ptr, section_len, FOLL_FORCE);
    if (bytes_count != section_len)
    {
        kfree(memory_ptr);
        return -EPERM;
    }
    
    // compute hash of bytes from memory_ptr to memory_ptr + mem_sec_len...
    
    kfree(memory_ptr);
    
    return 0;
}

int inspect_pid(int pid)
{
    int ret;
    struct vm_area_struct* vma;
    struct task_struct* task;
    struct mm_struct* mm;
    struct list_head* memory_sections_list;
    
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

out_mm_unlock:
    mmap_read_unlock(mm);
    mmput(mm);
out_put_task:
    put_task_struct(task);
out:
    clear_list(memory_sections_list);
    
    return ret;
}

static struct timer_list my_timer;
static unsigned long timer_period = 5 * HZ;

void my_timer_callback(struct timer_list* timer)
{
    int ret, i;
    
    for (i = 0; i < monitored_pids_count; ++i)
    {
        ret = inspect_pid(monitored_pids[i]);
        if (ret != 0)
            printk(KERN_ERR "%sError %d while inspecting PID %d\n", LOG_PREFIX, ret, monitored_pids[i]);
    }
    
    mod_timer(timer, jiffies + timer_period);   
}

static int __init proc_integrity_init(void)
{
    timer_setup(&my_timer, my_timer_callback, 0);
    mod_timer(&my_timer, jiffies + timer_period);
    
    return 0;
}

static void __exit proc_integrity_exit(void)
{
    del_timer(&my_timer);
}

module_init(proc_integrity_init);
module_exit(proc_integrity_exit);

MODULE_LICENSE("GPL");
