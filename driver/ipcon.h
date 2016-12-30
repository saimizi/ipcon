/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_H__
#define __IPCON_H__

#define NETLINK_IPCON 29

#define IPCON_MAX_POINT_NAME	128

#define IPCON_MAX_GROUP		32
#define IPCON_AUOTO_GROUP	(IPCON_MAX_GROUP + 1)

struct ipcon_point {
	char name[IPCON_MAX_POINT_NAME];
	unsigned int group;
};

enum MSG_TYPE {
	IPCON_GET_SELFID = 0x11,
	IPCON_SRV_REG = 0x12,
	IPCON_SRV_UNREG = 0x13,
	IPCON_SRV_DUMP = 0x14,
	IPCON_SRV_RESLOVE = 0x15,
	IPCON_USER = 0x16,
	IPCON_MULICAST_EVENT = 0x17,
	MSG_MAX,
};

#define IPCON_MC_GROUP_KERN	(1)

enum IPCON_KERN_EVENT {
	IPCON_SRV_ADD,
	IPCON_SRV_REMOVE
};

struct ipcon_kern_event {
	enum IPCON_KERN_EVENT	event;
#ifdef __KERNEL__
	u32 port;
#else
	__u32 port;
#endif
};

struct ipcon_kern_rsp {
	union {
		unsigned int group;
		struct {
			unsigned int grp;
#ifdef __KERNEL__
			u32 port;
#else
			__u32 port;
#endif
		};
	};
};


#endif
