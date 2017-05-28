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

#ifdef CONFIG_DEBUG_FS
#include "ipcon_debugfs.h"
#endif

DEFINE_MUTEX(ipcon_mutex);

static struct sock *ipcon_nl_sock;
static struct ipcon_tree_node *cp_tree_root;
static unsigned long int group_bitflag;
static struct ipcon_msghdr *group_msgs_cache[32];


struct ipcon_cmd_ops {
	__u32 type;
	int (*doit)(struct sk_buff *, struct ipcon_info *);
	int (*dumpit)(struct sk_buff *, struct ipcon_info *);
	int (*calcit)(struct sk_buff *, struct ipcon_info *);
};


static const struct nla_policy ipcon_policy[] = IPCON_POLICY_DEF;


struct ipcon_msghdr *dup_ipcon_msghdr(struct ipcon_msghdr *im,
					gfp_t flags)
{
	struct ipcon_msghdr *result = NULL;

	if (!im)
		return NULL;

	result = kmalloc(im->ipconmsg_len, flags);
	if (!result)
		return NULL;

	memcpy(result, im, im->ipconmsg_len);

	return result;
}

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

struct ipcon_tree_node *ipcon_lookup_unlock(char *name)
{
	return cp_lookup(cp_tree_root, name);
}

#ifdef CONFIG_DEBUG_FS
struct ipcon_msghdr *ipcon_get_group1(void)
{
	return group_msgs_cache[1];
}
#endif

void ipcon_lock(void)
{
	mutex_lock(&ipcon_mutex);
}

void ipcon_unlock(void)
{
	mutex_unlock(&ipcon_mutex);
}

/*
 * This function is called from another context.
 */
static int ipcon_netlink_notify(struct notifier_block *nb,
				  unsigned long state,
				  void *_notify)
{
	struct netlink_notify *n = _notify;
	struct ipcon_kern_event *ike = NULL;
	struct ipcon_msghdr *im = NULL;
	struct ipcon_tree_node *nd = NULL;

	if (!n)
		return 0;

	if (n->protocol != NETLINK_IPCON)
		return 0;

	if (state != NETLINK_URELEASE)
		return 0;

	im = alloc_ipconmsg(sizeof(struct ipcon_kern_event), GFP_ATOMIC);
	if (!im)
		return 0;

	ipcon_ref(&im);
	ike = IPCONMSG_DATA(im);

	/*
	 * If removed point is a registerred service. unregster it and inform
	 * user space.
	 */
	mutex_lock(&ipcon_mutex);
	nd = cp_lookup_by_port(cp_tree_root, n->portid);

	if (nd) {
		ike->event = IPCON_SRV_REMOVE;
		ike->port = nd->port;
		ike->group = nd->srv.group;
		if (nd->srv.group > 0) {
			unreg_group(nd->srv.group);
			ipcon_unref(&group_msgs_cache[nd->srv.group]);
		}

		strcpy(ike->name, nd->srv.name);
		im->rport = 0;

		cp_detach_node(&cp_tree_root, nd);
#ifdef CONFIG_DEBUG_FS
		ipcon_debugfs_remove_srv(nd);
#endif
		cp_free_node(nd);

		ipcon_info("Remove node: %s port: %lu group:%u\n",
			ike->name, (unsigned long)ike->port, ike->group);

		ipcon_multicast(0, IPCON_MC_GROUP_KERN, im,
			im->ipconmsg_len, GFP_ATOMIC);
	}


	ike->event = IPCON_POINT_REMOVE;
	ike->port = n->portid;
	ike->group = 0;
	ike->name[0] = '\0';

	ipcon_multicast(0, IPCON_MC_GROUP_KERN, im,
			im->ipconmsg_len, GFP_ATOMIC);

	mutex_unlock(&ipcon_mutex);

	ipcon_unref(&im);

	return 0;
}

static struct notifier_block ipcon_netlink_notifier = {
	.notifier_call = ipcon_netlink_notify,
};

int ipcon_nl_init(void)
{
	int ret = 0;
	struct netlink_kernel_cfg cfg = {
		.input	= ipcon_rcv,
		.flags = NL_CFG_F_NONROOT_RECV | NL_CFG_F_NONROOT_SEND,
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

#ifdef CONFIG_DEBUG_FS
	if (ipcon_debugfs_init(&group_bitflag))
		ipcon_err("Failed to init debugfs.\n");
#endif

	return ret;
}

void ipcon_nl_exit(void)
{

#ifdef CONFIG_DEBUG_FS
	ipcon_debugfs_exit();
#endif

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

		skb = alloc_skb(NLMSG_SPACE(size), flags);
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

		/*
		 * If no process suscribes the group,
		 * just return as success.
		 */
		if ((ret > 0) || (ret == -ESRCH))
			ret = 0;

	} while (0);

	/* Caching the last multicast message */
	if (!ret) {
		struct ipcon_msghdr *im = (struct ipcon_msghdr *)data;

		ipcon_unref(&group_msgs_cache[group]);
		ipcon_ref(&im);
		group_msgs_cache[group] = im;
	}

	return ret;
}


static int ipcon_get_selfid(struct sk_buff *skb, struct ipcon_info *info)
{
	return 0;
}

static int ipcon_srv_reg(struct sk_buff *skb, struct ipcon_info *info)
{
	return 0;
}

static int ipcon_srv_unreg(struct sk_buff *skb, struct ipcon_info *info)
{
	return 0;
}

static int ipcon_srv_reslove(struct sk_buff *skb, struct ipcon_info *info)
{
	return 0;
}

static int ipcon_grp_reg(struct sk_buff *skb, struct ipcon_info *info)
{
	return 0;
}

static int ipcon_grp_unreg(struct sk_buff *skb, struct ipcon_info *info)
{
	return 0;
}

static int ipcon_grp_reslove(struct sk_buff *skb, struct ipcon_info *info)
{
	return 0;
}

static int ipcon_user(struct sk_buff *skb, struct ipcon_info *info)
{
	BUG();
}

static int ipcon_grp_msg(struct sk_buff *skb, struct ipcon_info *info)
{
	return 0;
}

#define type2idx(type)	(type - IPCON_BASE)
struct ipcon_cmd_ops ipcon_cmd_table[] = {
	[type2idx(IPCON_GET_SELFID)]	= { .doit = ipcon_get_selfid },
	[type2idx(IPCON_SRV_REG)]	= { .doit = ipcon_srv_reg },
	[type2idx(IPCON_SRV_UNREG)]	= { .doit = ipcon_srv_unreg },
	[type2idx(IPCON_SRV_RESLOVE)]	= { .doit = ipcon_srv_reslove },
	[type2idx(IPCON_GRP_REG)]	= { .doit = ipcon_grp_reg},
	[type2idx(IPCON_GRP_UNREG)]	= { .doit = ipcon_grp_unreg },
	[type2idx(IPCON_GRP_RESLOVE)]	= { .doit = ipcon_grp_reslove },
	[type2idx(IPCON_USER)]		= { .doit = ipcon_user },
	[type2idx(IPCON_GRP_MSG)]	= { .doit = ipcon_grp_msg},
};

static int ipcon_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int type;
	int err = 0;

	do {
		struct nlattr *attrbuf[IPCON_ATTR_MAX];
		struct ipcon_info info;

		type = nlh->nlmsg_type;

		if (type >= MSG_MAX || type < IPCON_BASE) {
			ipcon_err("Wrong msg type:%x portid: %lu\n",
				type, (unsigned long)nlh->nlmsg_pid);
			error = -EINVAL;
			break;
		}

		err = nlmsg_parse(nlh, 0, attrbuf,
				IPCON_ATTR_MAX - 1, ipcon_policy);
		if (err < 0)
			break;

		info.snd_seq = nlh->nlmsg_seq;
		info.snd_port = NETLINK_CB(skb).portid;
		info.nlh = nlh;
		info.attrs = attr_table;

		if (ipcon_cmd_table[type2idx(type)].doit)
			err = ipcon_cmd_table[type2idx(type)].doit(skb, &info);
		else
			error = -EAFNOSUPPORT;

	} while (0);

	return  err;
}

void ipcon_rcv(struct sk_buff *skb)
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
	netlink_rcv_skb(skb, &ipcon_rcv_msg);
	mutex_unlock(&ipcon_mutex);
}
