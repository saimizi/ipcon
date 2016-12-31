/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <net/sock.h>
#include <net/netlink.h>
#include <asm/bitops.h>

#include "ipcon.h"
#include "ipcon_nl.h"
#include "ipcon_tree.h"
#include "ipcon_dbg.h"

DEFINE_MUTEX(ipcon_mutex);

static struct sock *ipcon_nl_sock;
static struct ipcon_tree_node *cp_tree_root;
static long int group_bitflag;


static int ipcon_multicast(u32 pid, unsigned int group,
		void *data, size_t size, gfp_t flags);

static inline int group_inuse(int group)
{
	return test_bit(group - 1, &group_bitflag);
}

static inline void reg_group(int group)
{
	set_bit(group - 1, &group_bitflag);
}

static inline void unreg_group(int group)
{
	clear_bit(group - 1, &group_bitflag);
}

static int ipcon_netlink_notify(struct notifier_block *nb,
				  unsigned long state,
				  void *_notify)
{
	struct netlink_notify *n = _notify;

	if (n) {
		if (n->protocol == NETLINK_IPCON) {
			struct ipcon_kern_event ike;

			if (state == NETLINK_URELEASE) {
				ike.event = IPCON_SRV_REMOVE;
				ike.port = n->portid;

				ipcon_multicast(0,
					IPCON_MC_GROUP_KERN,
					&ike,
					sizeof(ike),
					GFP_KERNEL);
			}

			ipcon_info(
				"notify: protocol: %d  portid: %d state: %lx\n",
				n->protocol,
				n->portid,
				state);
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

	set_bit(IPCON_MC_GROUP_KERN - 1, &group_bitflag);
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

int ipcon_unicast(u32 pid, int type, int seq, void *data, size_t size)
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
		 * netlink_unicast() called from nlmsg_unicast()
		 * takes ownership of the skb and frees it itself.
		 */
		ret = nlmsg_unicast(ipcon_nl_sock, skb, pid);

		if (ret > 0)
			ret = 0;

	} while (0);

	return ret;
}

static int ipcon_multicast(u32 pid, unsigned int group,
		void *data, size_t size, gfp_t flags)
{
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh = NULL;
	int ret = 0;

	do {
		if (!ipcon_nl_sock || !group) {
			ret = -EINVAL;
			break;
		}

		skb = alloc_skb(NLMSG_SPACE(size),
				GFP_ATOMIC);
		if (!skb) {
			ret = -ENOMEM;
			break;
		}

		nlh = nlmsg_put(skb, pid, 0, IPCON_MULICAST_EVENT, size, 0);
		if (!nlh) {
			ret = -ENOMEM;
			kfree_skb(skb);
			break;
		}

		memcpy(nlmsg_data(nlh), data, size);
		nlmsg_end(skb, nlh);

		/*
		 * netlink_broadcast_filtered() called from nlmsg_multicast
		 * takes ownership of the skb and frees it itself.
		 */
		ret = nlmsg_multicast(ipcon_nl_sock, skb, pid, group, flags);

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
		struct ipcon_kern_rsp ikr;
		struct ipcon_msghdr *im = NULL;

		switch (type) {
		case IPCON_GET_SELFID:
			selfid = NETLINK_CB(skb).portid;
			error = ipcon_unicast(selfid,
						type,
						nlh->nlmsg_seq++,
						&selfid,
						sizeof(selfid));
			ipcon_dbg("IPCON_POINT_SELFID: SELFID= %lu.\n",
					(unsigned long)selfid);
			break;
		case IPCON_SRV_REG:
			ip = NLMSG_DATA(nlh);
			if (!ip ||
				!strlen(ip->name) ||
				(ip->group > IPCON_AUOTO_GROUP) ||
				(ip->group == IPCON_MC_GROUP_KERN)) {

				error = -EINVAL;

			} else {
				memset(&ikr, 0, sizeof(ikr));
				ikr.group = ip->group;

				switch (ikr.group) {
				case 0:
					/* No group required */
					break;
				case IPCON_AUOTO_GROUP:
					/*
					 * Auto group id
					 * The lowest position returned from
					 * ffs() is 1
					 */
					ikr.group = ffs(~group_bitflag);
					set_bit(ikr.group, &group_bitflag);
					break;
				default: /* required group id */
					if (group_inuse(ikr.group))
						error = -EEXIST;
					else
						reg_group(ikr.group);

					break;
				}

				if (error)
					break;

				nd = cp_alloc_node(ip, nlh->nlmsg_pid);
				if (!nd) {
					error = -ENOMEM;
				} else {
					nd->group = ikr.group;
					error = cp_insert(&cp_tree_root, nd);
				}

				if (error) {
					if (nd)
						cp_free_node(nd);

					if (ikr.group)
						unreg_group(ikr.group);

					ipcon_err("Service register fail.(%d)\n",
							error);
				} else {
					ipcon_info("%s@%d(%d) registerred.\n",
							nd->point.name,
							nd->port,
							nd->point.group);

					error = ipcon_unicast(
							NETLINK_CB(skb).portid,
							type,
							nlh->nlmsg_seq++,
							(void *)&ikr,
							sizeof(ikr));

					/* if success do not send nlmsgerr */
					if (error && ikr.group)
						unreg_group(ikr.group);
				}
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
				if (nd->point.group)
					clear_bit(ip->group, &group_bitflag);

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
				memset(&ikr, 0, sizeof(ikr));
				nd = cp_lookup(cp_tree_root, srv_name);
				if (!nd) {
					error = -EINVAL;
					break;
				}

				ikr.group = nd->group;
				ikr.port = nd->port;
				error = ipcon_unicast(
						nlh->nlmsg_pid,
						type,
						nlh->nlmsg_seq++,
						&ikr,
						sizeof(ikr));
			}
			break;
		case IPCON_SRV_DUMP:
			cp_print_tree(cp_tree_root);
			break;
		case IPCON_MULICAST_EVENT:
			im = NLMSG_DATA(nlh);

			nd = cp_lookup_by_port(cp_tree_root, nlh->nlmsg_pid);
			if (!nd) {
				error = -EINVAL;
				break;
			}

			if (!nd->group || nd->group > 32) {
				error = -EINVAL;
				break;
			}

			error = ipcon_multicast(
					nlh->nlmsg_pid,
					nd->group,
					im,
					im->total_size,
					GFP_ATOMIC);

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
