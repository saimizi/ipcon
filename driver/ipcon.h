/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_H__
#define __IPCON_H__

#ifdef __KERNEL__
#include <net/netlink.h>
#include "ipcon_dbg.h"
#endif

#define NETLINK_IPCON 29

#define IPCON_MAX_NAME_LEN	32
#define IPCON_MAX_MSG_LEN	512

#define IPCON_MAX_GROUP		64

enum {
	IPCON_BASE		= 16,
	IPCON_GET_SELFID	= 16,
	IPCON_SRV_REG,
	IPCON_SRV_UNREG,
	IPCON_SRV_RESLOVE,
	IPCON_GRP_REG,
	IPCON_GRP_UNREG,
	IPCON_GRP_RESLOVE,
	IPCON_USER,
	IPCON_GRP_MSG,
	IPCON_MAX
};

enum {
	IPCON_ATTR_RPORT,
	IPCON_ATTR_SELFID,
	IPCON_ATTR_PORT,
	IPCON_ATTR_GRP,
	IPCON_ATTR_GRP_NAME,
	IPCON_ATTR_SRV_NAME,
	IPCON_ATTR_DATA,
	IPCON_ATTR_FLAG,
	IPCON_ATTR_KEVENT,
	IPCON_ATTR_MAX
};

/* IPCON kernel event (group 1) */
#define IPCON_MC_GROUP_KERN	(1)
enum IPCON_KERN_EVENT {
	IPCON_POINT_REMOVE,
	IPCON_SRV_ADD,
	IPCON_SRV_REMOVE
};

#define IPCON_POLICY_DEF {						\
	[IPCON_ATTR_RPORT] = {.type = NLA_U32},				\
	[IPCON_ATTR_SELFID] = {.type = NLA_U32},			\
	[IPCON_ATTR_PORT] = {.type = NLA_U32},				\
	[IPCON_ATTR_GROUP] = {.type = NLA_U32},				\
	[IPCON_ATTR_GRP_NAME] = {.type = NLA_NUL_STRING,		\
				.len = IPCON_MAX_NAME_LEN - 1},		\
	[IPCON_ATTR_SRV_NAME] = {.type = NLA_NUL_STRING,		\
				.len = IPCON_MAX_NAME_LEN - 1},		\
	[IPCON_ATTR_DATA] = {.type = NLA_BINARY,			\
			.len = IPCON_MAX_MSG_LEN},			\
	[IPCON_ATTR_FLAG] = {.type = NLA_FLAG},				\
	[IPCON_ATTR_KEVENT] = {.type = NLA_U8},				\
}


#endif /* __IPCON_H__ */
