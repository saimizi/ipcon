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

static int ipcon_netlink_notify(struct notifier_block *nb,
				  unsigned long state,
				  void *_notify)
{
	struct netlink_notify *n = _notify;

	if (n) {
		if (n->protocol == NETLINK_IPCON) {
			ipcon_info("notify: protocol: %d  portid: %d state: %lx\n",
				n->protocol, n->portid, state);
		}
	}

	return 0;
}

static struct notifier_block ipcon_netlink_notifier = {
	.notifier_call = ipcon_netlink_notify,
};

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

	ret = netlink_register_notifier(&ipcon_netlink_notifier);
	if (ret) {
		netlink_kernel_release(ipcon_nl_sock);
		ipcon_nl_sock = NULL;
	}

	return ret;
}

void ipcon_nl_exit(void)
{

	netlink_unregister_notifier(&ipcon_netlink_notifier);

	if (ipcon_nl_sock)
		netlink_kernel_release(ipcon_nl_sock);

	ipcon_nl_sock = NULL;

	if (cp_tree_root)
		cp_free_tree(cp_tree_root);
}

int ipcon_nl_send_msg(u32 pid, int type, int seq,
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

		if (ret > 0)
			ret = 0;

	} while (0);

	return ret;
}

static int ipcon_msg_handler(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int type;
	int error = 0;

	type = nlh->nlmsg_type;

	if (type >= MSG_MAX) {
		ipcon_err("Wrong msg type:%x portid: %lu\n",
				type, (unsigned long)nlh->nlmsg_pid);
		error = -EINVAL;
	} else {
		struct ipcon_tree_node *nd = NULL;
		struct ipcon_point *ip = NULL;
		char *srv_name = NULL;
		u32 selfid = 0;

		switch (type) {
		case IPCON_GET_SELFID:
			selfid = NETLINK_CB(skb).portid;
			error = ipcon_nl_send_msg(selfid,
						type,
						nlh->nlmsg_seq++,
						&selfid,
						sizeof(selfid));
			ipcon_dbg("IPCON_POINT_SELFID: SELFID= %lu.\n",
					(unsigned long)selfid);
			break;
		case IPCON_SRV_REG:
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

			break;
		case IPCON_SRV_UNREG:
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

			if (error) {
				ipcon_err("%s@%d unregistered failed (%d).\n",
						ip->name,
						nlh->nlmsg_pid,
						error);
			} else {
				cp_free_node(nd);
				ipcon_info("%s@%d unregistered.\n",
						ip->name,
						(int)nlh->nlmsg_pid);
			}

			break;
		case IPCON_SRV_RESLOVE:
			srv_name = NLMSG_DATA(nlh);
			if (!srv_name || !strlen(srv_name)) {
				error = -EINVAL;
			} else {
				nd = cp_lookup(cp_tree_root, srv_name);
				if (!nd)
					error = -EINVAL;
				else
					error = ipcon_nl_send_msg(
							nlh->nlmsg_pid,
							type,
							nlh->nlmsg_seq++,
							&nd->port,
							sizeof(nd->port));
			}
			break;
		case IPCON_SRV_DUMP:
			cp_print_tree(cp_tree_root);
			break;
		default:
			error = -EINVAL;
			ipcon_err("Unknow msg type: %x\n", type);
		};
	}

	ipcon_dbg("%s-%d error=%d\n", __func__, __LINE__, error);
	return  error;
}

void ipcon_nl_rcv_msg(struct sk_buff *skb)
{
	mutex_lock(&ipcon_mutex);
	netlink_rcv_skb(skb, &ipcon_msg_handler);
	mutex_unlock(&ipcon_mutex);
}
