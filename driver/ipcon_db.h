/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_TREE_H__
#define __IPCON_TREE_H__

#include <linux/rbtree.h>
#include <linux/string.h>
#include <linux/types.h>
#include "ipcon.h"
#include "ipcon_dbg.h"

#define IPN_HASH_BIT	4
struct ipcon_group_info {
	struct hlist_node igi_hname;
	struct hlist_node igi_hgroup;
	unsigned int group;
	char name[IPCON_MAX_NAME_LEN];
	struct sk_buff *last_grp_msg;
}

struct ipcon_peer_node {
	char name[IPCON_MAX_NAME_LEN];
	__u32 port;
	__u32 ctrl_port;
	DECLARE_HASHTABLE(ipn_name_ht, IPN_HASH_BIT);
	DECLARE_HASHTABLE(ipn_group_ht, IPN_HASH_BIT);
	struct hlist_node ipn_hname;
	struct hlist_node ipn_hport;
};

#define IPD_HASH_BIT	10

struct ipcon_peer_db {
	rwlock_t lock;
	unsigned long grp_bitmap[BITS_TO_LONGS(IPCON_MAX_GROUP)];
	DECLARE_HASHTABLE(ipd_name_ht, IPD_HASH_BIT);
	DECLARE_HASHTABLE(ipd_port_ht, IPD_HASH_BIT);
};


static inline void ipd_rd_lock(struct ipcon_peer_db *db)
{
	read_lock(&db->lock);
};

static inline void ipd_rd_unlock(struct ipcon_peer_db *db)
{
	read_unlock(&db->lock);
};

static inline void ipd_wr_lock(struct ipcon_peer_db *db)
{
	write_lock(&db->lock);
};

static inline int ipd_wr_trylock(struct ipcon_peer_db *db)
{
	return write_trylock(&db->lock);
};

static inline void ipd_wr_unlock(struct ipcon_peer_db *db)
{
	write_unlock(&db->lock);
};

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


struct ipcon_group_info *igi_alloc(char *name, gfp_t flag);
void igi_del(struct ipcon_group_info *igi);
void igi_free(struct ipcon_group_info *igi)

struct ipcon_peer_node *ipn_alloc(__u32 port, __u32 ctrl_port, char *name);
void ipn_free(struct ipcon_peer_node *ipn);
struct ipcon_group_info *ipn_lookup_byname(struct ipcon_peer_node *ipn,
					char *grp_name);
struct ipcon_group_info *ipn_lookup_bygroup(struct ipcon_peer_node *ipn,
					unsigned long group);

int ipn_insert(struct ipcon_peer_node *ipn, struct ipcon_group_info *igi);
void ipn_del(struct ipcon_peer_node *ipn);

struct ipcon_peer_db *ipd_alloc(gfp_t flag);
struct ipcon_peer_node *ipd_lookup_byname(struct ipcon_peer_db *ipd,
					char *name);
struct ipcon_peer_node *ipd_lookup_byport(struct ipcon_peer_db *ipd,
					u32 port);
int ipd_insert(struct ipcon_peer_db *ipd, struct ipcon_peer_node *ipn);
void ipd_free(struct ipcon_peer_db *ipd);

static inline struct ipcon_group_info *ipd_get_igi(struct ipcon_peer_db *ipd,
					u32 port, unsigned int group)
{
	return ipn_lookup_bygroup(ipd_lookup_byport(ipd, port), group);
}


#endif
