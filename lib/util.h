#ifndef __UTIL_H__
#define __UTIL_H__
#include <linux/types.h>

struct link_entry {
	struct link_entry *prev;
	struct link_entry *next;
	struct link_entry *head;
};

struct link_entry_head {
	struct link_entry le;
	__u32 cnt;
};


#define LINK_ENTRY(a) ((struct link_entry *)a)
#define LINK_ENTRY_HEAD(a) ((struct link_entry_head *)a)

void le_init(struct link_entry *le);
void lh_init(struct link_entry_head *lh);
void le_addtail(struct link_entry_head *head, struct link_entry *new);
void *le_next(struct link_entry *le);
void *le_remove(struct link_entry *le);
struct link_entry_head *le_gethead(struct link_entry *le);
__u32 le_getcnt(struct link_entry_head *le);

#endif /*__UTIL_H__*/
