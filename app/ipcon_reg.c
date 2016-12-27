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
#include "libipcon.h"

#define ipcon_debug(fmt, ...)	printf("[ipcon_reg] "fmt, ##__VA_ARGS__)
#define ipcon_info(fmt, ...)	printf("[ipcon_reg] "fmt, ##__VA_ARGS__)
#define ipcon_err(fmt, ...)	printf("[ipcon_reg] "fmt, ##__VA_ARGS__)

static int rcv_msg(int sock, struct sockaddr_nl *src, struct nlmsghdr *nlh);

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
	IPCON_HANDLER handler;

	do {
		handler = ipcon_create_handler();
		if (!handler) {
			ipcon_err("Failed to init libipcon.\n");
			break;
		}

		ipcon_debug("Register %s.\n", argv[1]);
		if (argc > 1) {
			ret = ipcon_register_service(handler, argv[1]);
			if (ret)
				ipcon_err("Failed to register %s: %s (%d)\n",
					argv[1], strerror(-ret), ret);
			else
				ipcon_err("Service %s registered.\n", argv[1]);
		} else {
			ipcon_err("No service name specified.\n");
		}

	} while (0);

	exit(0);

}
