#ifndef __IPCON_DEBUGFS_H__
#define __IPCON_DEBUGFS_H__

int __init ipcon_debugfs_init(unsigned long int *);
void __exit ipcon_debugfs_exit(void);
int ipcon_debugfs_add_srv(struct ipcon_tree_node *nd,
		struct ipcon_msghdr **cached_msg);
int ipcon_debugfs_remove_srv(struct ipcon_tree_node *nd);

#endif
