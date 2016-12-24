/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_H__
#define __IPCON_H__

#define NETLINK_IPCON 29

#define IPCON_MAX_POINT_NAME	128

struct ipcon_point {
	char name[IPCON_MAX_POINT_NAME];
};

enum MSG_TYPE {
	IPCON_POINT_REG = 0x11,
	IPCON_POINT_UNREG = 0x12,
	IPCON_POINT_DUMP = 0x13,
	MSG_STR,
	MSG_MAX,
	MSG_DUMMY
};

#endif
