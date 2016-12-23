#ifndef __IPCON_H__
#define __IPCON_H__

#define NETLINK_IPCON 29

struct srv_info {
	char name[128];
	int port;
};

enum MSG_TYPE {
	SRV_REGISTER = 0x11,
	MSG_STR,
	MSG_MAX,
	MSG_DUMMY
};

#endif
