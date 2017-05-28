/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <net/sock.h>
#include <net/netlink.h>
#include <asm/bitops.h>

#include "ipcon.h"
#include "ipcon_nl.h"
#include "ipcon_db.h"
#include "ipcon_dbg.h"

#ifdef CONFIG_DEBUG_FS
#include "ipcon_debugfs.h"
#endif

DEFINE_MUTEX(ipcon_mutex);

static struct sock *ipcon_nl_sock;
static struct ipcon_peer_db *ipcon_db;

struct ipcon_cmd_ops {
	__u32 type;
	int (*doit)(struct sk_buff *, struct ipcon_info *);
	int (*dumpit)(struct sk_buff *, struct ipcon_info *);
	int (*calcit)(struct sk_buff *, struct ipcon_info *);
};

static const struct nla_policy ipcon_policy[] = IPCON_POLICY_DEF;



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
		.groups = IPCON_MAX_GROUP;
		.input	= ipcon_rcv,
		.flags  = NL_CFG_F_NONROOT_RECV | NL_CFG_F_NONROOT_SEND,
	};

	ipcon_db = ipd_alloc(GFP_KERNEL);
	if (!ipcon_db) {
		ipcon_err("Failed to create alloc ipcon storage.\n");
		return -ENOMEM;
	}

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

int ipcon_unicast(struct sk_buff *skb, u32 port)
{
	return nlmsg_unicast(ipcon_nl_sock, skb, port);
}

int ipcon_reply(struct sk_buff *skb, struct ipcon_info *info)
{
	return ipcon_unicast(skb, info->snd_port);
}

static int ipcon_multicast(struct sk_buff *skb, u32 port,
			unsigned int group, gfp_t flags)
{
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh = NULL;
	int ret = 0;

	ret = nlmsg_multicast(ipcon_nl_sock, skb, pid, group, flags);

	/*
	 * If no process suscribes the group,
	 * just return as success.
	 */
	if ((ret > 0) || (ret == -ESRCH))
		ret = 0;

	/*
	 * Caching the last multicast message
	 */
	if (!ret) {
		struct ipcon_group_info igi = NULL;

		ipd_wr_lock(ipcon_db);

		igi = ipd_get_igi(ipd, port, group);
		kfree_skb(igi->last_grp_msg);
		skb_get(skb);
		igi->last_grp_msg = skb;

		ipd_wr_unlock(ipcon_db);
	}

	return ret;
}

/* Return pointer to user data */
void *ipconmsg_put(struct sk_buff *skb, u32 seq, int type, int flags)
{
	struct nlmsghdr *nlh;

	nlh = nlmsg_put(skb, pid, seq, type, flags);
	if (!nlh)
		return NULL;

	return (char *)nlmsg_data(nlh);
}

static inline int ipconmsg_end(struct sk_buff *skb, void *hdr)
{
	return nlmsg_end(skb, hdr - NLMSG_HDRLEN);
}

static inline void ipconmsg_cancel(struct sk_buff *skb, void *hdr)
{
	if (hdr)
		nlmsg_cancel(skb, hdr - NLMSG_HDRLEN);
}


static int ipcon_get_selfid(struct sk_buff *skb, struct ipcon_info *info)
{
	int ret = 0;

	do {
		struct sk_buff *msg = NULL;
		void *hdr = NULL;

		msg = nlmsg_new(IPCON_MSG_DEFAULT_SIZE, GFP_KERNEL);
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		hdr = ipconmsg_put(msg, info->snd_seq++, IPCON_GET_SELFID, 0);
		if (!hdr) {
			nlmsg_free(msg);
			ret = -ENOBUFS;
			break;
		}

		nla_put_u32(msg, IPCON_ATTR_PORT, info->snd_port);

		nlmsg_end(msg, hdr);
		ret = ipcon_reply(msg, info);

	} while (0);

	return ret;
}

static int ipcon_peer_reg(struct sk_buff *skb, struct ipcon_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_NAME_LEN];
	u32 port;
	u32 ctl_port;

	do {
		struct ipcon_peer_node *ipn = NULL;

		if (!info->attrs[IPCON_ATTR_PORT] ||
			!info->attrs[IPCON_ATTR_PEER_NAME]) {

			ret = -EINVAL;
			break;
		}

		ctl_port = info->snd_port;
		port = nla_get_u32(info->attrs[IPCON_ATTR_PORT]);
		nla_strcpy(name, info->attrs[IPCON_ATTR_PEER_NAME],
				IPCON_MAX_NAME_LEN);

		ipn = ipn_alloc(port, ctl_port, name);
		if (!ipn) {
			ret = -ENOMEM;
			break;
		}

		ipd_wr_lock(ipcon_db);
		ret = ipd_insert(ipcon_db, ipn);
		ipd_wr_unlock(ipcon_db);

	} while (0);

	return ret;
}

static int ipcon_peer_reslove(struct sk_buff *skb, struct ipcon_info *info)
{
	int ret = 0;
	char name[IPCON_MAX_NAME_LEN];
	u32 port = 0;
	u32 ctl_port;

	do {
		struct ipcon_peer_node *ipn = NULL;
		struct sk_buff *msg = NULL;
		void *hdr = NULL;

		if (!info->attrs[IPCON_ATTR_PEER_NAME]) {
			ret = -EINVAL;
			break;
		}

		nla_strcpy(name, info->attrs[IPCON_ATTR_PEER_NAME],
				IPCON_MAX_NAME_LEN);

		ipd_rd_lock(ipcon_db);
		ipn = ipd_lookup_byname(ipcon_db, name);
		if (ipn)
			port = ipn->port;
		ipd_rd_unlock(ipcon_db);

		/* Port of user peer will not be 0 */
		if (!port) {
			ret = -ENOENT;
			break;
		}

		msg = nlmsg_new(IPCON_MSG_DEFAULT_SIZE, GFP_KERNEL);
		if (!msg) {
			ret = -ENOMEM;
			break;
		}

		hdr = ipconmsg_put(msg, info->snd_seq++, IPCON_PEER_RESLOVE, 0);
		if (!hdr) {
			nlmsg_free(msg);
			ret = -ENOBUFS;
			break;
		}

		nla_put_u32(msg, IPCON_ATTR_PORT, port);
		nlmsg_end(msg, hdr);
		ret = ipcon_reply(msg, info);

	} while (0);

	return ret;
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
	[type2idx(IPCON_PEER_REG)]	= { .doit = ipcon_peer_reg },
	[type2idx(IPCON_PEER_RESLOVE)]	= { .doit = ipcon_peer_reslove},
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
