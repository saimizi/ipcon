#ifndef __LIBIPCON_H__
#define __LIBIPCON_H__

#include "ipcon.h"

#define IPCON_HANDLER	void *

#define IPCON_MAX_USR_GROUP	5

#define IPCON_NORMAL_MSG	IPCON_MSG_UNICAST
#define IPCON_GROUP_MSG		IPCON_MSG_MULTICAST


struct ipcon_msg {
	__u32 type;
	char group[IPCON_MAX_GRP_NAME_LEN];
	__u32 port;
	char buf[IPCON_MAX_MSG_LEN];
	__u32 len;
};


IPCON_HANDLER ipcon_create_handler(void);
void ipcon_free_handler(IPCON_HANDLER handler);
int ipcon_register_service(IPCON_HANDLER handler, char *name);
int ipcon_unregister_service(IPCON_HANDLER handler, char *name);
int ipcon_find_service(IPCON_HANDLER handler, char *name, __u32 *srv_port);
int ipcon_rcv(IPCON_HANDLER handler, struct ipcon_msg *im);
int ipcon_send_unicast(IPCON_HANDLER handler, __u32 port,
				void *buf, size_t size);
int ipcon_register_group(IPCON_HANDLER handler, char *name);
int ipcon_unregister_group(IPCON_HANDLER handler, char *name);
int ipcon_join_group(IPCON_HANDLER handler, char *name, int rcv_last_msg);
int ipcon_leave_group(IPCON_HANDLER handler, char *name);
__u32 ipcon_get_selfport(IPCON_HANDLER handler);
struct ipcon_srv *ipcon_get_selfsrv(IPCON_HANDLER handler);
int ipcon_getfd(IPCON_HANDLER handler);
int ipcon_find_group(IPCON_HANDLER handler, char *name, __u32 *groupid);
int ipcon_send_multicast(IPCON_HANDLER handler, char *name, void *buf,
			size_t size);
#endif
