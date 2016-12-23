/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_H__
#define __IPCON_H__

#define NETLINK_IPCON 29

struct ipcon_point {
	char name[128];
	int port;
};

enum MSG_TYPE {
	IPCON_POINT_REG = 0x11,
	MSG_STR,
	MSG_MAX,
	MSG_DUMMY
};

#endif
