#ifndef PROC_INTEGRITY_LIST_UTILS_H 
#define PROC_INTEGRITY_LIST_UTILS_H

#include <linux/list.h>

void clear_list(struct list_head* list);
bool are_lists_identical(struct list_head* lhs, struct list_head* rhs);

#endif  // PROC_INTEGRITY_LIST_UTILS_H
