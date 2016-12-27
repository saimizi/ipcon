#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "libipcon_internal.h"

static struct nlmsghdr *alloc_nlmsg(unsigned long payload_size)
{
	struct nlmsghdr *nlh = NULL;

	if (payload_size > 0) {
		nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(payload_size));
		if (nlh) {
			nlh->nlmsg_len = NLMSG_SPACE(payload_size);
			nlh->nlmsg_pid = 0;
			nlh->nlmsg_flags = 0;
		}
	}

	return nlh;
}

static int send_msg(int sock, struct sockaddr_nl *dest, struct nlmsghdr *nlh)
{
	struct iovec iov;
	struct msghdr msg;
	ssize_t len = 0;
	int ret = 0;

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&msg, 0, sizeof(struct msghdr));
	msg.msg_name = (void *)dest;
	msg.msg_namelen = sizeof(struct sockaddr_nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	len = sendmsg(sock, &msg, 0);
	if (len < 0) {
		libipcon_err("Msg sending fail: %s (%d).\n",
				strerror(errno), errno);
		ret = -1;
	}

	return ret;
}

int send_unicast_msg(struct ipcon_mng_info *imi, int port, enum MSG_TYPE mt,
			void *payload, unsigned long payload_size)
{
	struct sockaddr_nl dest;
	struct nlmsghdr *nlh = NULL;

	if (payload_size >= MAX_PAYLOAD_SIZE) {
		libipcon_err("%s payload_size over.\n", __func__);
		return -1;
	}

	nlh = alloc_nlmsg(payload_size);
	if (nlh == NULL) {
		libipcon_err("Failed to alloc netlink msg.\n");
		return -ENOMEM;
	}

	nlh->nlmsg_type = mt;
	nlh->nlmsg_pid = imi->local.nl_pid;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	memcpy(NLMSG_DATA(nlh), (char *)payload, (size_t)payload_size);

	dest.nl_family = AF_NETLINK;
	dest.nl_pid = (__u32)port;
	dest.nl_groups = 0;

	return send_msg(imi->sk, &dest, nlh);
}

static int rcv_msg(int sock, struct sockaddr_nl *src, struct nlmsghdr *nlh)
{
	struct iovec iov;
	struct msghdr msg;
	ssize_t len = 0;
	int ret = 0;

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	msg.msg_name = (void *)src;
	msg.msg_namelen = sizeof(struct sockaddr_nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	len = recvmsg(sock, &msg, 0);
	if (len < 0)
		ret = -1;

	return ret;
}

int rcv_unicast_msg(struct ipcon_mng_info *imi, int port, void *buf,
			unsigned long size)
{
	struct nlmsghdr *nlh = NULL;
	struct sockaddr_nl dst;
	int ret = 0;

	if (!imi || !buf || size > MAX_PAYLOAD_SIZE)
		return -EINVAL;

	nlh = alloc_nlmsg(size);
	if (nlh == NULL) {
		libipcon_err("Failed to alloc netlink msg.\n");
		return -ENOMEM;
	}

	dst.nl_family = AF_NETLINK;
	dst.nl_pid = (__u32)port;
	dst.nl_groups = 0;

	ret = rcv_msg(imi->sk, &dst, nlh);
	if (!ret) {
		char *p = NLMSG_DATA(nlh);

		if (size > 0)
			memcpy(buf, p, size);
	}

	free(nlh);

	return ret;
}

int wait_response(struct ipcon_mng_info *imi, enum MSG_TYPE mt)
{
	int ret = 0;
	struct nlmsgerr nlerr;

	if (!imi)
		return -EINVAL;

	/* FIXME: Add timeout... */
	do {
		ret = rcv_unicast_msg(imi, 0, &nlerr, sizeof(nlerr));
		if (!ret) {
			if (nlerr.msg.nlmsg_type == mt) {
				ret = nlerr.error;
				break;
			}
		} else {
			break;
		}
	} while (1);

	return ret;
}
