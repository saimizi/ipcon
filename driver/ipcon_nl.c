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

/*
 * This function is called from another context.
 */
static int ipcon_netlink_notify(struct notifier_block *nb,
				  unsigned long state,
				  void *_notify)
{
	struct netlink_notify *n = _notify;

	if (n) {
		if (n->protocol == NETLINK_IPCON) {
			struct ipcon_kern_event *ike = NULL;
			struct ipcon_msghdr *im = NULL;

			if (state == NETLINK_URELEASE) {
				im = alloc_ipconmsg(
						sizeof(struct ipcon_kern_event),
						GFP_ATOMIC);

				if (im) {
					struct ipcon_tree_node *nd = NULL;

					ike = IPCONMSG_DATA(im);

					/*
					 * If removed point is a registerred
					 * service. unregster it and inform user
					 * space.
					 */
					mutex_lock(&ipcon_mutex);
					nd = cp_lookup_by_port(cp_tree_root,
							n->portid);
					if (nd) {
						ike->event = IPCON_SRV_REMOVE;
						ike->port = nd->port;
						ike->group = nd->srv.group;
						strcpy(ike->name, nd->srv.name);
						im->rport = 0;

						cp_detach_node(&cp_tree_root,
								nd);
						cp_free_node(nd);

						ipcon_multicast(0,
							IPCON_MC_GROUP_KERN,
							im,
							im->ipconmsg_len,
							GFP_ATOMIC);
					}
					mutex_unlock(&ipcon_mutex);


					/*
					 * Inform point removed.
					 */
					ike->event = IPCON_POINT_REMOVE;
					ike->port = n->portid;
					ike->group = 0;
					ike->name[0] = '\0';

					ipcon_multicast(0,
						IPCON_MC_GROUP_KERN,
						im,
						im->ipconmsg_len,
						GFP_KERNEL);

					kfree(im);
				}
			}

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
		struct ipcon_srv *ip = NULL;
		char *srv_name = NULL;
		struct ipcon_msghdr *im = NULL;
		struct ipcon_kern_event *ike = NULL;

		switch (type) {
		case IPCON_GET_SELFID:
			im = alloc_ipconmsg(0, GFP_ATOMIC);
			im->selfid = NETLINK_CB(skb).portid;
			ipcon_dbg("IPCON_GET_SELFID: id=%lu\n",
					(unsigned long)im->selfid);
			error = ipcon_unicast(im->selfid,
						type,
						nlh->nlmsg_seq++,
						im,
						im->ipconmsg_len);
			kfree(im);
			break;

		case IPCON_SRV_REG:
			if (!NLMSG_DATA(nlh)) {
				error = -EINVAL;
				break;
			}

			ip = IPCONMSG_DATA((struct ipcon_msghdr *)
						NLMSG_DATA(nlh));

			if (!ip || !strlen(ip->name) ||
				(ip->group > IPCON_AUOTO_GROUP) ||
				(ip->group == IPCON_MC_GROUP_KERN)) {

				error = -EINVAL;
				break;
			}

			ipcon_dbg("IPCON_SRV_REG: name:%s group=%u\n",
					ip->name, ip->group);

			im = alloc_ipconmsg(0, GFP_ATOMIC);
			if (!im) {
				error = -ENOMEM;
				break;
			}

			switch (ip->group) {
			case 0:
				/* No group required */
				break;
			case IPCON_AUOTO_GROUP:
				/*
				 * Auto group id
				 * The LSB returned from ffs() is 1, while LSB
				 * in set_bit() is 0, so do not use set_bit()
				 * directly, use reg_group() instead.
				 */
				ip->group = ffs(~group_bitflag);
				reg_group(ip->group);
				break;
			default: /* required group id */
				if (group_inuse(ip->group))
					error = -EEXIST;
				else
					reg_group(ip->group);

				break;
			}

			if (error) {
				kfree(im);
				break;
			}

			nd = cp_alloc_node(ip, nlh->nlmsg_pid);
			if (!nd) {
				error = -ENOMEM;
				kfree(im);
				break;
			}

			im->group = nd->srv.group;
			error = cp_insert(&cp_tree_root, nd);
			if (error) {
				cp_free_node(nd);

				if (im->group)
					unreg_group(im->group);

				kfree(im);
				break;
			}

			ipcon_info("SRVREG: port=%lu, name=%s grp=%u\n",
					(unsigned long)nd->port,
					nd->srv.name,
					nd->srv.group);
			ipcon_dbg("SRVREG: group_bitflag=0x%lx\n",
					group_bitflag);

			error = ipcon_unicast(
					NETLINK_CB(skb).portid,
					type,
					nlh->nlmsg_seq++,
					im,
					im->ipconmsg_len);

			if (error) {
				cp_detach_node(&cp_tree_root, nd);
				cp_free_node(nd);

				if (im->group)
					unreg_group(im->group);
			}

			kfree(im);

			/* Inform user space that service added */
			if (error)
				break;

			im = alloc_ipconmsg(
				sizeof(struct ipcon_kern_event),
				GFP_ATOMIC);

			if (!im) {
				ipcon_err("IPCON_SRV_UNREG notify failed\n");
				break;
			}

			ike = IPCONMSG_DATA(im);
			ike->event = IPCON_SRV_ADD;
			ike->port =  nd->port;
			ike->group =  nd->srv.group;
			strcpy(ike->name, nd->srv.name);
			im->rport = 0;

			ipcon_multicast(0,
				IPCON_MC_GROUP_KERN,
				im,
				im->ipconmsg_len,
				GFP_ATOMIC);

			kfree(im);
			break;

		case IPCON_SRV_UNREG:
			im = NLMSG_DATA(nlh);
			if (!im) {
				error = -EINVAL;
				break;
			}

			ip = IPCONMSG_DATA(im);
			if (!ip || !strlen(ip->name)) {
				error = -EINVAL;
				break;
			}

			nd = cp_lookup(cp_tree_root, ip->name);
			if (!nd)
				error = -EINVAL;
			else
				error = cp_detach_node(&cp_tree_root, nd);

			if (error)
				break;

			if (nd->srv.group)
				unreg_group(nd->srv.group);


			/* Inform user space that service removed */
			im = alloc_ipconmsg(
				sizeof(struct ipcon_kern_event),
				GFP_ATOMIC);

			if (!im) {
				ipcon_err("IPCON_SRV_UNREG notify failed\n");
				cp_free_node(nd);
				break;
			}

			ike = IPCONMSG_DATA(im);
			ike->event = IPCON_SRV_REMOVE;
			ike->port =  nd->port;
			ike->group =  nd->srv.group;
			strcpy(ike->name, nd->srv.name);
			im->rport = 0;

			ipcon_multicast(0,
				IPCON_MC_GROUP_KERN,
				im,
				im->ipconmsg_len,
				GFP_ATOMIC);
			kfree(im);

			cp_free_node(nd);

			ipcon_dbg("SRVUNREG: group_bitflag=0x%lx\n",
					group_bitflag);
			break;

		case IPCON_SRV_RESLOVE:
			srv_name = IPCONMSG_DATA((struct ipcon_msghdr *)
					NLMSG_DATA(nlh));
			if (!srv_name || !strlen(srv_name)) {
				error = -EINVAL;
				break;
			}

			nd = cp_lookup(cp_tree_root, srv_name);
			if (!nd) {
				error = -ESRCH;
				break;
			}

			im = alloc_ipconmsg(0, GFP_ATOMIC);
			if (!im) {
				error = -ENOMEM;
				break;
			}

			im->srv.group = nd->srv.group;
			im->srv.port = nd->port;
			error = ipcon_unicast(
					nlh->nlmsg_pid,
					type,
					nlh->nlmsg_seq++,
					im,
					im->ipconmsg_len);

			kfree(im);
			break;

		case IPCON_GROUP_RESLOVE:
			im = NLMSG_DATA(nlh);
			if (!im) {
				error = -EINVAL;
				break;
			}
			if (group_inuse(im->group))
				error = 0;
			else
				error = -ESRCH;

			break;

		case IPCON_SRV_DUMP:
			cp_print_tree(cp_tree_root);
			break;

		case IPCON_MULICAST_EVENT:
			im = NLMSG_DATA(nlh);
			if (!im) {
				error = -EINVAL;
				break;
			}

			nd = cp_lookup_by_port(cp_tree_root, nlh->nlmsg_pid);
			if (!nd) {
				error = -EINVAL;
				break;
			}

			if ((nd->srv.group == IPCON_MC_GROUP_KERN) ||
					(nd->srv.group > 32)) {
				error = -EINVAL;
				break;
			}

			error = ipcon_multicast(
					nlh->nlmsg_pid,
					nd->srv.group,
					im,
					im->ipconmsg_len,
					GFP_ATOMIC);

			/*
			 * If no process suscribes the group,
			 * just return as success.
			 */
			if (error == -ESRCH)
				error = 0;
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
	/*
	 * Sequentialize the message receiving from user application.
	 * this protects cp_tree_root and group_bitflag so that no
	 * seperated protetion needed.
	 *
	 * The possible potential confilc processing is
	 * - Other user process's asychronizing call.
	 * - netlink notifier.
	 *   see ipcon_netlink_notifier().
	 */
	mutex_lock(&ipcon_mutex);
	netlink_rcv_skb(skb, &ipcon_msg_handler);
	mutex_unlock(&ipcon_mutex);
}
