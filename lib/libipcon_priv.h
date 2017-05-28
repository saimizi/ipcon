#ifndef __LIBIPCON_PRIV_H__
#define __LIBIPCON_PRIV_H__

#include "libipcon.h"
#include "util.h"

#define IPCON_ANY_CMD	IPCON_CMD_MAX
#define IPCON_ANY_PORT	0xFFFFFFFF

struct ipcon_msg_entry {
	struct link_entry le;
	struct nl_msg *msg;
};

struct ipcon_channel {
	struct nl_sock *sk;
	struct link_entry_head mq;
	__u32 port;
	pthread_mutex_t mutex;
};

struct ipcon_group_info {
	char name[IPCON_MAX_NAME_LEN];
	__u32 groupid;
	struct ipcon_group_info *next;
};

struct ipcon_peer_handler {
	char name[IPCON_MAX_NAME_LEN];
	struct ipcon_channel chan;
	struct ipcon_channel ctrl_chan;
	struct ipcon_group_info *grp;
};

static inline void ipcon_ctrl_lock(struct ipcon_peer_handler *iph)
{
	pthread_mutex_lock(&iph->ctrl_chan.mutex);
}

static inline void ipcon_ctrl_unlock(struct ipcon_peer_handler *iph)
{
	pthread_mutex_unlock(&iph->ctrl_chan.mutex);
}

static inline void ipcon_com_lock(struct ipcon_peer_handler *iph)
{
	pthread_mutex_lock(&iph->chan.mutex);
}

static inline void ipcon_com_unlock(struct ipcon_peer_handler *iph)
{
	pthread_mutex_unlock(&iph->chan.mutex);
}

#define handler_to_iph(h) ((struct ipcon_peer_handler *) h)
#define iph_to_handler(i) ((IPCON_HANDLER) i)

#endif
