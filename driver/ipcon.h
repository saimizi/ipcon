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
	__u32 port;
};

struct ipcon_kern_rsp {
	union {
		unsigned int group;
		struct {
			unsigned int grp;
			__u32 port;
		};
	};
};

struct ipcon_msghdr {
	__u32 rport;
	__u32 total_size;
	__u32 size;
};

#define IPCON_MSG_ALIGNTO	4U
#define IPCON_MSG_ALIGN(len) \
	(((len)+IPCON_MSG_ALIGNTO-1) & ~(IPCON_MSG_ALIGNTO-1))
#define IPCON_MSG_HDRLEN \
	((int) IPCON_MSG_ALIGN(sizeof(struct ipcon_msghdr)))
#define IPCON_MSG_LENGTH(len) ((len) + IPCON_MSG_HDRLEN)
#define IPCON_MSG_SPACE(len) IPCON_MSG_ALIGN(IPCON_MSG_LENGTH(len))
#define IPCON_MSG_DATA(ipconh) \
		((void *)(((char *)ipconh) + IPCON_MSG_LENGTH(0)))

#define IPCON_MSG_OK(ipconh, len) \
		((len) >= (int)sizeof(struct ipcon_msghdr) && \
		(nlh)->total_size >= sizeof(struct ipcon_msghdr) && \
		(nlh)->total_size <= (len))

#define IPCON_MSG_NEXT(ipconh, len) \
		((len) -= IPCON_MSG_ALIGN((ipconh)->total_size), \
		(struct ipcon_msghdr *)(((char *)(ipconh)) + \
		NLMSG_ALIGN((ipconh)->total_len)))

#endif
