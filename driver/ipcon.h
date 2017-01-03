/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_H__
#define __IPCON_H__

#define NETLINK_IPCON 29

#define IPCON_MAX_SRV_NAME_LEN	16

#define IPCON_MAX_GROUP		32
#define IPCON_AUOTO_GROUP	(IPCON_MAX_GROUP + 1)

struct ipcon_srv {
	char name[IPCON_MAX_SRV_NAME_LEN];
	unsigned int group;
};

enum MSG_TYPE {
	IPCON_GET_SELFID = 0x11,
	IPCON_SRV_REG = 0x12,
	IPCON_SRV_UNREG = 0x13,
	IPCON_SRV_DUMP = 0x14,
	IPCON_SRV_RESLOVE = 0x15,
	IPCON_GROUP_RESLOVE = 0x16,
	IPCON_USER = 0x17,
	IPCON_MULICAST_EVENT = 0x18,
	MSG_MAX,
};

/* IPCON kernel event (group 1) */
#define IPCON_MC_GROUP_KERN	(1)
enum IPCON_KERN_EVENT {
	IPCON_POINT_REMOVE,
	IPCON_SRV_ADD,
	IPCON_SRV_REMOVE
};

struct ipcon_kern_event {
	enum IPCON_KERN_EVENT	event;
	__u32 port;
	/* The following are only meaningful in IPCON_SRV_* msg */
	char name[IPCON_MAX_SRV_NAME_LEN];
	unsigned int group;
};

/* IPCON message format */
struct ipcon_msghdr {
	__u32 ipconmsg_len;	/* Total msg length including header */
	__u32 size;		/*User data real size */
	__u32 auth_key;		/*
				 * Authencation key between kernel and
				 * user space for service.
				 */
	union {
		__u32 rport;	/* Real port number in IPCON_MULICAST_EVENT */
		__u32 selfid;	/* self portid in IPCON_GET_SELFID */
		unsigned int group;
				/* IPCON_SRV_REG and IPCON_GROUP_RESLOVE */
		struct {
			unsigned int group;
			__u32 port;
		} srv;		/* Service information in reslove */
	};
};

#define MAX_IPCONMSG_LEN	(sizeof(struct ipcon_msghdr) + 512)

#define IPCONMSG_ALIGNTO	4U
#define IPCONMSG_ALIGN(len) \
	(((len)+IPCONMSG_ALIGNTO-1) & ~(IPCONMSG_ALIGNTO-1))
#define IPCONMSG_HDRLEN \
	((int) IPCONMSG_ALIGN(sizeof(struct ipcon_msghdr)))
#define IPCONMSG_LENGTH(len) ((len) + IPCONMSG_HDRLEN)
#define IPCONMSG_SPACE(len) IPCONMSG_ALIGN(IPCONMSG_LENGTH(len))
#define IPCONMSG_DATA(ipconh) \
		((void *)(((char *)ipconh) + IPCONMSG_LENGTH(0)))

#define IPCONMSG_OK(ipconh, len) \
		((len) >= (int)sizeof(struct ipcon_msghdr) && \
		(ipconh)->total_size >= sizeof(struct ipcon_msghdr) && \
		(ipconh)->total_size <= (len))

#define IPCONMSG_NEXT(ipconh, len) \
		((len) -= IPCONMSG_ALIGN((ipconh)->total_size), \
		(struct ipcon_msghdr *)(((char *)(ipconh)) + \
		IPCONMSG_ALIGN((ipconh)->total_len)))

#define IPCON_VALID_PAYLOAD_LENGTH(size) \
		(((__u32)IPCONMSG_SPACE(size) <= MAX_IPCONMSG_LEN))

#ifdef __KERNEL__
static inline struct ipcon_msghdr *alloc_ipconmsg(__u32 size, gfp_t flags)
{
	struct ipcon_msghdr *result = NULL;

	if (!IPCON_VALID_PAYLOAD_LENGTH(size))
		return NULL;

	result = kmalloc(IPCONMSG_SPACE(size), flags);
	if (result) {
		memset(result, 0, sizeof(*result));
		result->ipconmsg_len = IPCONMSG_SPACE(size);
		result->size = size;
	}

	return result;
}
#else
static inline struct ipcon_msghdr *alloc_ipconmsg(__u32 size)
{
	struct ipcon_msghdr *result = NULL;

	if (!IPCON_VALID_PAYLOAD_LENGTH(size))
		return NULL;

	result = malloc(IPCONMSG_SPACE(size));
	if (result) {
		memset(result, 0, sizeof(*result));
		result->ipconmsg_len = IPCONMSG_SPACE(size);
		result->size = size;
	}

	return result;
}
#endif

#define max_size_nlerr(size) \
		(size > sizeof(struct nlmsgerr) ? \
		size : sizeof(struct nlmsgerr))


#endif /* __IPCON_H__ */
