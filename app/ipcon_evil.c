#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>

#include "ipcon.h"

#define ipcon_debug(fmt, ...)	printf("[ipcon] "fmt, ##__VA_ARGS__)
#define ipcon_info(fmt, ...)	printf("[ipcon] "fmt, ##__VA_ARGS__)
#define ipcon_err(fmt, ...)	printf("[ipcon] "fmt, ##__VA_ARGS__)

/* #define NLPORT	(pthread_self() << 16 | getpid()) */
/* #define NLPORT	(getpid()) */
#define NLPORT	(0)

static struct nlmsghdr *alloc_nlmsg(int payload_size);

static int rcv_msg(int sock, struct sockaddr_nl *src, struct nlmsghdr *nlh);

static int snd_msg(int sock, struct sockaddr_nl *dest, struct nlmsghdr *nlh)
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
		ipcon_err("%s : %s (%d).\n", __func__, strerror(errno), errno);
		ret = -1;
	}

	return ret;
}

#define MAX_PAYLOAD_SIZE	(4 * 1024)
static int snd_unicast_msg(int sock, int fake_port, int port, enum MSG_TYPE mt, void *payload,
				int payload_size)
{
	struct sockaddr_nl dest;
	struct nlmsghdr *nlh = NULL;

	if (payload_size >= MAX_PAYLOAD_SIZE) {
		ipcon_err("%s payload_size over.\n", __func__);
		return -1;
	}

	nlh = alloc_nlmsg(MAX_PAYLOAD_SIZE);
	if (nlh == NULL) {
		ipcon_err("Failed to alloc netlink msg.\n");
		return -1;
	}
	nlh->nlmsg_type = mt;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_pid = fake_port;
	memcpy(NLMSG_DATA(nlh), (char *)payload, payload_size);

	dest.nl_family = AF_NETLINK;
	dest.nl_pid = port;
	dest.nl_groups = 0;

	return snd_msg(sock, &dest, nlh);
}

static struct nlmsghdr *alloc_nlmsg(int payload_size)
{
	struct nlmsghdr *nlh = NULL;

	if (payload_size > 0) {
		nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(payload_size));
		if (nlh) {
			nlh->nlmsg_len = NLMSG_SPACE(payload_size);
			nlh->nlmsg_pid = NLPORT;
			nlh->nlmsg_flags = 0;
		}
	}

	return nlh;
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

int main(int argc, char *argv[])
{
	int ret = 0;
	int sock = 0;
	struct sockaddr_nl nladdr;
	__u32 target_port;
	char *msg = NULL;


	if (argc <= 2)
		exit(-EINVAL);

	target_port = atoi(argv[1]);
	msg = argv[2];


	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_IPCON);
	if (sock < 0) {
		ipcon_err("Failed to open netlink socket.\n");
		ret = -1;
		goto main_out;
	}

	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid	 = 0;
	nladdr.nl_groups = 0;

	ret = bind(sock, (struct sockaddr *) &nladdr, sizeof(nladdr));
	if (ret < 0) {
		ipcon_err("Failed to bind netlink socket.\n");
		ret = -1;
		goto main_after_socket_open;
	}


	/* Pretend kernel to send multicast message */
	snd_unicast_msg(sock, 0, target_port, IPCON_MULICAST_EVENT,
			msg, strlen(msg) + 1);

	exit(0);

main_after_socket_open:
	close(sock);

main_out:
	exit(ret);
}
