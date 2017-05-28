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
	return 0;
}

static struct notifier_block ipcon_netlink_notifier = {
	.notifier_call = ipcon_netlink_notify,
};


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
	int ret = 0;

	ret = nlmsg_multicast(ipcon_nl_sock, skb, port, group, flags);

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
		struct ipcon_group_info *igi = NULL;

		ipd_wr_lock(ipcon_db);

		igi = ipd_get_igi(ipcon_db, port, group);
		kfree_skb(igi->last_grp_msg);
		skb_get(skb);
		igi->last_grp_msg = skb;

		ipd_wr_unlock(ipcon_db);
	}

	return ret;
}

/* Return pointer to user data */
void *ipconmsg_put(struct sk_buff *skb, u32 port, u32 seq, int type, int flags)
{
	struct nlmsghdr *nlh;

	nlh = nlmsg_put(skb, port, seq, type, IPCON_HDRLEN, flags);
	if (!nlh)
		return NULL;

	return (char *)nlmsg_data(nlh);
}

static inline void ipconmsg_end(struct sk_buff *skb, void *hdr)
{
	nlmsg_end(skb, hdr - IPCON_HDRLEN - NLMSG_HDRLEN);
}

static inline void ipconmsg_cancel(struct sk_buff *skb, void *hdr)
{
	if (hdr)
		nlmsg_cancel(skb, hdr - IPCON_HDRLEN - NLMSG_HDRLEN);
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

		hdr = ipconmsg_put(msg, 0, info->snd_seq++,
				IPCON_GET_SELFID, 0);
		if (!hdr) {
			nlmsg_free(msg);
			ret = -ENOBUFS;
			break;
		}

		nla_put_u32(msg, IPCON_ATTR_PORT, info->snd_port);

		ipconmsg_end(msg, hdr);
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
		nla_strlcpy(name, info->attrs[IPCON_ATTR_PEER_NAME],
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

	do {
		struct ipcon_peer_node *ipn = NULL;
		struct sk_buff *msg = NULL;
		void *hdr = NULL;

		if (!info->attrs[IPCON_ATTR_PEER_NAME]) {
			ret = -EINVAL;
			break;
		}

		nla_strlcpy(name, info->attrs[IPCON_ATTR_PEER_NAME],
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

		hdr = ipconmsg_put(msg, 0, info->snd_seq++,
				IPCON_PEER_RESLOVE, 0);
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

		if (type >= IPCON_MAX || type < IPCON_BASE) {
			ipcon_err("Wrong msg type:%x portid: %lu\n",
				type, (unsigned long)nlh->nlmsg_pid);
			err = -EINVAL;
			break;
		}

		err = nlmsg_parse(nlh, 0, attrbuf,
				IPCON_ATTR_MAX - 1, ipcon_policy);
		if (err < 0)
			break;

		info.snd_seq = nlh->nlmsg_seq;
		info.snd_port = NETLINK_CB(skb).portid;
		info.nlh = nlh;
		info.attrs = attrbuf;

		if (ipcon_cmd_table[type2idx(type)].doit)
			err = ipcon_cmd_table[type2idx(type)].doit(skb, &info);
		else
			err = -EAFNOSUPPORT;

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

int ipcon_nl_init(void)
{
	int ret = 0;
	struct netlink_kernel_cfg cfg = {
		.groups = IPCON_MAX_GROUP,
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

	reg_group(ipcon_db, IPCON_MC_GROUP_KERN);
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
	netlink_kernel_release(ipcon_nl_sock);
	ipd_free(ipcon_db);
}
