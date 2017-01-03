#ifndef __LIBIPCON_INTERNAL_H__
#define __LIBIPCON_INTERNAL_H__

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

#include "libipcon.h"

#define libipcon_dbg(fmt, ...)	\
	fprintf(stderr, "[libipcon] DEBUG: "fmt, ##__VA_ARGS__)
#define libipcon_info(fmt, ...) \
	fprintf(stderr, "[libipcon] INFO: "fmt, ##__VA_ARGS__)
#define libipcon_warn(fmt, ...) \
	fprintf(stderr, "[libipcon] WARN: "fmt, ##__VA_ARGS__)
#define libipcon_err(fmt, ...) \
	fprintf(stderr, "[libipcon] ERROR: "fmt, ##__VA_ARGS__)

/* #define NLPORT	((__u32)getpid()) */
#define NLPORT	(0)

#ifndef SOL_NETLINK
#define SOL_NETLINK	270
#endif

enum ipcon_type {
	IPCON_TYPE_USER,
	IPCON_TYPE_SERVICE,
	MAX_IPCON_TYPE
};

struct ipcon_msg_link {
	struct nlmsghdr *nlh;
	struct sockaddr_nl from;
	struct ipcon_msg_link *next;
};

struct ipcon_mng_info {
	pthread_mutex_t mutex;
	int sk;
	__u32 port;
	enum ipcon_type type;
	struct ipcon_srv srv;
	struct ipcon_msg_link *msg_queue;
};

static void free_ipcon_msg_link(struct ipcon_msg_link *iml)
{
	if (!iml)
		return;

	if (iml->nlh)
		free(iml->nlh);

	free(iml);
}

#define handler_to_info(a)	((struct ipcon_mng_info *) a)
#define info_to_handler(a)	((IPCON_HANDLER) a)

static unsigned int get_group(__u32 grp_mask)
{
	unsigned int grp = 0;

	while (grp_mask) {
		grp_mask = grp_mask >> 1;
		grp++;
	}

	return grp;
}

int send_unicast_msg(struct ipcon_mng_info *imi, __u32 port, __u16 flag,
		enum MSG_TYPE mt, void *payload, unsigned long payload_size);
int rcv_msg(struct ipcon_mng_info *imi, struct sockaddr_nl *from,
		struct nlmsghdr **nlh, __u32 max_msg_size);
int wait_err_response(struct ipcon_mng_info *imi, __u32 port, enum MSG_TYPE mt);
int queue_msg(struct ipcon_mng_info *imi, struct nlmsghdr *nlh,
		struct sockaddr_nl *from);
struct ipcon_msg_link *dequeue_msg(struct ipcon_mng_info *imi);
#endif
