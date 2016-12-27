/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_NETLINK_H__
#define __IPCON_NETLINK_H__

int ipcon_nl_init(void);
int ipcon_netlink_send_msg(int pid, int type, int seq,
				void *data, size_t size);
int ipcon_send_response(struct nlmsghdr *msg, int error);
void ipcon_nl_rcv_msg(struct sk_buff *skb);
void ipcon_nl_exit(void);
#endif
