#ifndef __LIBIPCON_INTERNAL_H__
#define __LIBIPCON_INTERNAL_H__

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "libipcon.h"

#define libipcon_dbg(fmt, ...)	\
	fprintf(stderr, "[libipcon] DEBUG: "fmt, ##__VA_ARGS__)
#define libipcon_info(fmt, ...) \
	fprintf(stderr, "[libipcon] INFO: "fmt, ##__VA_ARGS__)
#define libipcon_err(fmt, ...) \
	fprintf(stderr, "[libipcon] ERROR: "fmt, ##__VA_ARGS__)

#define NLPORT	((__u32)getpid())

enum ipcon_type {
	IPCON_TYPE_USER,
	IPCON_TYPE_SERVICE,
	MAX_IPCON_TYPE
};

struct ipcon_mng_info {
	int sk;
	enum ipcon_type type;
	struct ipcon_point *srv;
	struct sockaddr_nl local;
};

#define handler_to_info(a)	((struct ipcon_mng_info *) a)
#define info_to_handler(a)	((IPCON_HANDLER) a)

#define MAX_PAYLOAD_SIZE	(4 * 1024)
int send_unicast_msg(struct ipcon_mng_info *imi, __u32 port, __u16 flag,
		enum MSG_TYPE mt, void *payload, unsigned long payload_size);
int rcv_unicast_msg(struct ipcon_mng_info *imi, __u32 port,
			struct nlmsghdr **nlh);
int wait_err_response(struct ipcon_mng_info *imi, __u32 port, enum MSG_TYPE mt);
#endif
