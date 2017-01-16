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

	nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(payload_size));
	if (nlh) {
		nlh->nlmsg_len = NLMSG_SPACE(payload_size);
		nlh->nlmsg_pid = 0;
		nlh->nlmsg_seq = 0;
		nlh->nlmsg_flags = 0;
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

	if (payload_size >= MAX_IPCONMSG_LEN) {
		libipcon_err("%s payload_size over.\n", __func__);
		return -EINVAL;
	}

	nlh = alloc_nlmsg(payload_size);
	if (nlh == NULL) {
		libipcon_err("Failed to alloc netlink msg.\n");
		return -ENOMEM;
	}

	nlh->nlmsg_type = mt;
	nlh->nlmsg_pid = imi->port;
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
	struct iovec iov;
	struct msghdr msg;
	ssize_t len = 0;

	if (!imi || !nlh || max_msg_size > MAX_IPCONMSG_LEN)
		return -EINVAL;

	if (!max_msg_size)
		*nlh = alloc_nlmsg(MAX_IPCONMSG_LEN);
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
		ret = rcv_msg(imi, &from, &nlh, MAX_IPCONMSG_LEN);
		if (ret < 0)
			break;

		if (nlh->nlmsg_type != NLMSG_ERROR) {
			if (queue_msg(imi, nlh, &from))
				libipcon_warn("Received msg maybe lost.\n");
			continue;
		}

		nlerr = NLMSG_DATA(nlh);
		if (nlerr->msg.nlmsg_type == mt) {
			ret = nlerr->error;
			free(nlh);
			break;
		}

		free(nlh);
	} while (1);

	return ret;
}

int queue_msg(struct ipcon_mng_info *imi, struct nlmsghdr *nlh,
		struct sockaddr_nl *from)
{
	struct ipcon_msg_link *iml = NULL;

	libipcon_dbg("%s enter.\n", __func__);

	if (!imi || !nlh || !from)
		return -EINVAL;

	if (imi->msg_queue) {
		iml = imi->msg_queue;

		while (iml->next)
			iml = iml->next;

		iml->next = (struct ipcon_msg_link *)
			malloc(sizeof(struct ipcon_msg_link));

		if (!iml->next)
			return -ENOMEM;

		memset(iml->next, 0, sizeof(struct ipcon_msg_link));
		iml->next->nlh = nlh;
		memcpy(&iml->next->from, from, sizeof(struct sockaddr_nl));
	} else {
		imi->msg_queue = (struct ipcon_msg_link *)
			malloc(sizeof(struct ipcon_msg_link));

		if (!imi->msg_queue)
			return -ENOMEM;

		memset(imi->msg_queue, 0, sizeof(struct ipcon_msg_link));
		imi->msg_queue->nlh = nlh;
		memcpy(&imi->msg_queue->from, from, sizeof(struct sockaddr_nl));
	}

	return 0;
}

struct ipcon_msg_link *dequeue_msg(struct ipcon_mng_info *imi)
{
	struct ipcon_msg_link *iml = NULL;

	libipcon_dbg("%s enter.\n", __func__);

	if (!imi)
		return NULL;

	if (imi->msg_queue) {
		iml = imi->msg_queue;
		imi->msg_queue = iml->next;
		iml->next = NULL;
	}

	return iml;
}


int ipcon_unregister_service_unlock(struct ipcon_mng_info *imi)
{
	int ret = 0;
	struct ipcon_msghdr *im = NULL;
	struct ipcon_srv *srv = NULL;

	do {
		if (!imi) {
			ret = -EINVAL;
			break;
		}

		if (imi->type != IPCON_TYPE_SERVICE) {
			ret = -EINVAL;
			break;
		}

		im = alloc_ipconmsg(sizeof(struct ipcon_srv));
		if (!im) {
			ret = -ENOMEM;
			break;
		}

		srv = IPCONMSG_DATA(im);
		memcpy(srv, &imi->srv, sizeof(struct ipcon_srv));
		im->auth_key = imi->auth_key;

		ret = send_unicast_msg(imi,
				0,
				NLM_F_ACK | NLM_F_REQUEST,
				IPCON_SRV_UNREG,
				im,
				im->ipconmsg_len);
		if (ret < 0)
			break;

		ret = wait_err_response(imi, 0, IPCON_SRV_UNREG);
		if (!ret) {

			libipcon_dbg("Unregister %s success.\n",
					imi->srv.name);

			memset(&imi->srv, 0, sizeof(struct ipcon_srv));
			imi->type = IPCON_TYPE_USER;
		} else {
			libipcon_dbg("Unregister %s failed (%d).\n",
					imi->srv.name, ret);
		}

	} while (0);

	return ret;
}
