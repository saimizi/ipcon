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
			nlh->nlmsg_seq = 0;
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

int send_unicast_msg(struct ipcon_mng_info *imi, __u32 port, __u16 flag,
		enum MSG_TYPE mt, void *payload, unsigned long payload_size)
{
	struct sockaddr_nl dest;
	struct nlmsghdr *nlh = NULL;
	int ret = 0;

	if (payload_size >= MAX_PAYLOAD_SIZE) {
		libipcon_err("%s payload_size over.\n", __func__);
		return -EINVAL;
	}

	nlh = alloc_nlmsg(payload_size);
	if (nlh == NULL) {
		libipcon_err("Failed to alloc netlink msg.\n");
		return -ENOMEM;
	}

	nlh->nlmsg_type = mt;
	nlh->nlmsg_pid = imi->local.nl_pid;
	nlh->nlmsg_flags = flag;

	if (payload && (payload_size > 0))
		memcpy(NLMSG_DATA(nlh), (char *)payload, (size_t)payload_size);

	dest.nl_family = AF_NETLINK;
	dest.nl_pid = port;
	dest.nl_groups = 0;

	ret = send_msg(imi->sk, &dest, nlh);
	free(nlh);

	return ret;
}

int rcv_msg(struct ipcon_mng_info *imi, struct sockaddr_nl *from,
		struct nlmsghdr **nlh, __u32 max_msg_size)
{
	;
	struct iovec iov;
	struct msghdr msg;
	ssize_t len = 0;

	if (!imi || !nlh)
		return -EINVAL;

	if (!max_msg_size)
		*nlh = alloc_nlmsg(MAX_PAYLOAD_SIZE);
	else
		*nlh = alloc_nlmsg(max_msg_size);

	if (*nlh == NULL) {
		libipcon_err("Failed to alloc netlink msg.\n");
		return -ENOMEM;
	}

	iov.iov_base = (void *)(*nlh);
	iov.iov_len = (*nlh)->nlmsg_len;

	msg.msg_name = (void *)from;
	msg.msg_namelen = sizeof(*from);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	len = recvmsg(imi->sk, &msg, 0);
	if (len < 0)
		return -errno;

	return 0;
}

int wait_err_response(struct ipcon_mng_info *imi, __u32 port, enum MSG_TYPE mt)
{
	int ret = 0;
	struct nlmsgerr *nlerr;
	struct nlmsghdr *nlh = NULL;
	struct sockaddr_nl from;

	if (!imi)
		return -EINVAL;

	/* FIXME: Add timeout... */
	do {
		ret = rcv_msg(imi, &from, &nlh, sizeof(*nlerr));
		if (!ret) {
			if (nlh->nlmsg_type != NLMSG_ERROR) {
				free(nlh);
				nlh = NULL;
				continue;
			}

			nlerr = NLMSG_DATA(nlh);
			if (nlerr->msg.nlmsg_type == mt) {
				ret = nlerr->error;
				break;
			}

			free(nlh);
			nlh = NULL;
		} else {
			break;
		}
	} while (1);

	return ret;
}
