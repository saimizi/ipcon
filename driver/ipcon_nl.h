/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_NETLINK_H__
#define __IPCON_NETLINK_H__
#include <net/sock.h>

int ipcon_nl_init(void);
int ipcon_netlink_send_msg(int pid, int type, int seq,
				void *data, size_t size);
void ipcon_nl_rcv_msg(struct sk_buff *skb);
void ipcon_nl_exit(void);
struct ipcon_tree_node *ipcon_lookup_unlock(char *name);
void ipcon_lock(void);
void ipcon_unlock(void);

#ifdef CONFIG_DEBUG_FS
struct ipcon_msghdr *ipcon_get_group1(void);
#endif
#endif
