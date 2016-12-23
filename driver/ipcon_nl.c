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

int ipcon_send_response(int pid, int seq, int error)
{
	struct nlmsgerr nlerr;
	int ret = 0;

	memset(&nlerr, 0, sizeof(nlerr));

	nlerr.error = error;

	ret = ipcon_nl_send_msg(pid, NLMSG_ERROR, seq,
			(void *)&nlerr, sizeof(nlerr));

	return ret;
}

static int ipcon_msg_handler(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int type;
	int error = 0;

	type = nlh->nlmsg_type;

	if (type >= MSG_MAX) {
		ipcon_err("Wong msg type: %x\n", type);
		error = -EINVAL;
	} else {
		struct ipcon_tree_node *nd = NULL;

		switch (type) {
		case IPCON_POINT_REG:
			nd = cp_alloc_node(NLMSG_DATA(nlh));

			if (!nd)
				error = -ENOMEM;
			else
				error = cp_insert(&cp_tree_root, nd);

			if (error)
				ipcon_err("Failed to register point.(%d)\n",
						error);
			else
				ipcon_info("Point %s registered.\n",
						nd->point.name);
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

	return ipcon_send_response(nlh->nlmsg_pid, nlh->nlmsg_seq++, error);
}

void ipcon_nl_rcv_msg(struct sk_buff *skb)
{
	mutex_lock(&ipcon_mutex);
	netlink_rcv_skb(skb, &ipcon_msg_handler);
	mutex_unlock(&ipcon_mutex);
}
