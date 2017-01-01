#ifndef __LIBIPCON_H__
#define __LIBIPCON_H__

#include "ipcon.h"

#define IPCON_HANDLER	void *

struct ipcon_info {
	__u32 port;
	const struct ipcon_srv *srv;
};

IPCON_HANDLER ipcon_create_handler(void);
int ipcon_free_handler(IPCON_HANDLER handler);
int ipcon_register_service(IPCON_HANDLER handler, char *name,
				unsigned int group);
int ipcon_unregister_service(IPCON_HANDLER handler);
int ipcon_find_service(IPCON_HANDLER handler,
			char *name,
			__u32 *srv_port,
			unsigned int *group);
int ipcon_rcv(IPCON_HANDLER handler, __u32 *port,
		unsigned int *group, void **buf, __u32 max_msg_size);
int ipcon_send_unicast(IPCON_HANDLER handler, __u32 port,
				void *buf, size_t size);
int ipcon_send_multicast(IPCON_HANDLER handler, void *buf, size_t size);
int ipcon_join_group(IPCON_HANDLER handler, unsigned int group);
struct ipcon_info *ipcon_get_info(IPCON_HANDLER handler);
#endif
