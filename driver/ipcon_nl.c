/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <net/sock.h>
#include <net/netlink.h>

#include "ipcon.h"
#include "ipcon_nl.h"
#include "ipcon_tree.h"
#include "ipcon_dbg.h"

DEFINE_MUTEX(ipcon_mutex);

static struct sock *ipcon_nl_sock;
static struct ipcon_tree_node *cp_tree_root;

int ipcon_nl_init(void)
{
	int ret = 0;
	struct netlink_kernel_cfg cfg = {
		.input	= ipcon_nl_rcv_msg,
	};

	ipcon_nl_sock = netlink_kernel_create(&init_net, NETLINK_IPCON, &cfg);
	if (!ipcon_nl_sock) {
		ipcon_err("Failed to create netlink socket.\n");
		ret = -ENOMEM;
	}

	return ret;
}

void ipcon_nl_exit(void)
{
	if (ipcon_nl_sock)
		netlink_kernel_release(ipcon_nl_sock);

	ipcon_nl_sock = NULL;

	if (cp_tree_root)
		cp_free_tree(cp_tree_root);
}

int ipcon_nl_send_msg(int pid, int type, int seq,
				void *data, size_t size)
{
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh = NULL;
	int ret = -1;

	do {
		if (!ipcon_nl_sock)
			break;

		skb = alloc_skb(NLMSG_SPACE(size), GFP_ATOMIC);
		if (!skb)
			break;

		nlh = nlmsg_put(skb, 0, 0, 0, size, 0);
		if (!nlh) {
			kfree_skb(skb);
			break;
		}

		memcpy(nlmsg_data(nlh), data, size);
		nlh->nlmsg_seq = seq;
		nlh->nlmsg_type = type;

		/*
		 * netlink_unicast() takes ownership of the skb and
		 * frees it itself.
		 */
		ret = netlink_unicast(ipcon_nl_sock, skb, pid, 0);

	} while (0);

	return ret;
}

int ipcon_send_response(struct nlmsghdr *msg, int error)
{
	struct nlmsgerr nlerr;
	int ret = 0;

	if (!msg)
		return -EINVAL;

	memset(&nlerr, 0, sizeof(nlerr));

	nlerr.error = error;
	memcpy(&nlerr.msg, msg, sizeof(*msg));

	ret = ipcon_nl_send_msg(msg->nlmsg_pid, NLMSG_ERROR, msg->nlmsg_seq++,
			(void *)&nlerr, sizeof(nlerr));

	return ret;
}

static int ipcon_msg_handler(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int type;
	int error = 0;

	type = nlh->nlmsg_type;

	if (type >= MSG_MAX || !nlh->nlmsg_pid) {
		ipcon_err("Wrong msg type:%x portid: %lu\n",
				type, (unsigned long)nlh->nlmsg_pid);
		error = -EINVAL;
	} else {
		struct ipcon_tree_node *nd = NULL;
		struct ipcon_point *ip = NULL;

		switch (type) {
		case IPCON_POINT_REG:
			ip = NLMSG_DATA(nlh);
			if (!ip || !strlen(ip->name)) {
				error = -EINVAL;
			} else {
				nd = cp_alloc_node(ip, nlh->nlmsg_pid);
				if (!nd)
					error = -ENOMEM;
				else
					error = cp_insert(&cp_tree_root, nd);
			}

			if (error) {
				if (nd)
					cp_free_node(nd);
				ipcon_err("Failed to register point.(%d)\n",
						error);
			} else {
				ipcon_info("%s@%d registerred.\n",
						nd->point.name,
						nd->port);
			}

			error = ipcon_send_response(nlh, error);

			break;
		case IPCON_POINT_UNREG:
			ip = NLMSG_DATA(nlh);
			if (!ip || !strlen(ip->name)) {
				error = -EINVAL;
			} else {
				nd = cp_lookup(cp_tree_root, ip->name);
				if (!nd)
					error = -EINVAL;
				else
					error = cp_detach_node(&cp_tree_root,
								nd);
			}

			if (error)
				ipcon_err("%s@%d unregistered failed (%d).\n",
						ip->name,
						nlh->nlmsg_pid,
						error);
			else
				ipcon_info("%s@%d unregistered.\n",
						ip->name,
						(int)nlh->nlmsg_pid);

			error = ipcon_send_response(nlh, error);
			break;
		case IPCON_POINT_DUMP:
			cp_print_tree(cp_tree_root);
			break;
		case MSG_STR:
			ipcon_info("Rcev from port %d: %s\n",
				nlh->nlmsg_pid, (char *)NLMSG_DATA(nlh));
			break;
		default:
			error = -EINVAL;
			ipcon_err("Unknow msg type: %x\n", type);
		};
	}

	return  error;
}

void ipcon_nl_rcv_msg(struct sk_buff *skb)
{
	mutex_lock(&ipcon_mutex);
	netlink_rcv_skb(skb, &ipcon_msg_handler);
	mutex_unlock(&ipcon_mutex);
}
