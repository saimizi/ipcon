#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#ifdef SERVER_AUTO_RESTART
#include <signal.h>
#include <sys/wait.h>
#endif

#include "ipcon.h"
#include "libipcon.h"

#define ipcon_dbg(fmt, ...) \
	printf("[ipcon_sender] %s-%d " fmt, __func__, __LINE__,  ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	printf("[ipcon_sender] %s-%d "fmt, __func__, __LINE__, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	printf("[ipcon_sender] %s-%d "fmt, __func__, __LINE__, ##__VA_ARGS__)

__u32 srv_port;
unsigned int group;
int wait_response;

static int deal_srv_add(IPCON_HANDLER handler,
		struct ipcon_kern_event *ike)
{
	int ret = 0;

	if (!ike) {
		ret = -EINVAL;
	} else {
		if (!strcmp(ike->name, "ipcon_server") && !srv_port) {
			ipcon_dbg("found ipcon_server@%d\n", ike->port);
			srv_port = ike->port;
		}
	}

	return ret;
}

static int deal_srv_remove(IPCON_HANDLER handler,
		struct ipcon_kern_event *ike)
{
	int ret = 0;


	if (!ike) {
		ret = -EINVAL;
	} else {
		if (!strcmp(ike->name, "ipcon_server")) {
#ifdef SERVER_AUTO_RESTART
			pid_t pid;
#endif

			srv_port = 0;

			/*
			 * Maybe server is killed while we are waiting a
			 * response from it. clear the state.
			 */
			wait_response = 0;

#ifdef SERVER_AUTO_RESTART
			ipcon_err("ipcon server is sadly lost. restart it\n");

			pid = fork();
			if (!pid) {
				char const *cmd = "/usr/bin/ipcon_server";
				char const *argv[] = {cmd, NULL};

				execve(cmd, argv, NULL);
			}
#else
			ipcon_err("ipcon server is sadly lost. Pending...\n");
#endif
		}
	}

	return ret;
}

#ifdef SERVER_AUTO_RESTART
static void sig_handler(int sig)
{
	if (sig == SIGCHLD)
		wait(NULL);
}
#endif

int main(int argc, char *argv[])
{
	int ret = 0;
	IPCON_HANDLER handler;

	do {
		char *msg = NULL;
#ifdef SERVER_AUTO_RESTART
		struct sigaction sa;

		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
		sa.sa_handler = sig_handler;

		if (sigaction(SIGCHLD, &sa, NULL) == -1) {
			ipcon_err("Failed to regster signal handler.\n");
			break;
		}
#endif

		if (argc <= 1)
			break;

		msg = argv[1];

		handler = ipcon_create_handler();
		if (!handler) {
			ipcon_err("Failed to create libipcon handler.\n");
			break;
		}

		/*
		 * Register IPCON kernel event to monitor service
		 * "ipcon_server", this should be done before calling
		 * ipcon_find_service() so that detection will not be missed.
		 */
		ret = ipcon_join_group(handler, IPCON_MC_GROUP_KERN);
		if (ret < 0) {
			ipcon_err("Failed to join group %d %s(%d).\n",
					IPCON_MC_GROUP_KERN,
					strerror(-ret),
					ret);
			ipcon_free_handler(handler);
			break;
		}

		ret = ipcon_find_service(handler,
					"ipcon_server",
					&srv_port,
					&group);
		if (!ret) {
			ipcon_info(
				"Found service %s at port %lu (grp: %u).\n",
				"ipcon_server",
				(unsigned long)srv_port,
				group);
		}

		while (1) {
			char *buf = NULL;
			int len = 0;
			__u32 src_port = 0;

			/*
			 * ipcon kernel message may come during waiting for
			 * the response of server. so a wait_response is used to
			 * manage the state.
			 */
			if (srv_port && !wait_response) {
				ipcon_info("Send %s to server %d\n",
						msg, srv_port);

				ret = ipcon_send_unicast(handler,
						srv_port,
						msg,
						strlen(msg) + 1);

				/*
				 * Maybe fail because that ipcon_server is
				 * killed. that is OK, it will be detected by
				 * IPCON_SRV_REMOVE event.
				 */
				if (ret < 0)
					ipcon_err("Send msg fail.\n");
				else
					wait_response = 1;
			}

			len = ipcon_rcv(handler, &src_port, &group,
					(void **)&buf);

			if (len < 0) {
				ipcon_err("Receive msg fail.\n");
				ret = len;
				break;
			}

			if (group == IPCON_MC_GROUP_KERN) {
				struct ipcon_kern_event *ike =
					(struct ipcon_kern_event *)buf;

				switch (ike->event) {
				case IPCON_SRV_ADD:
					deal_srv_add(handler, ike);
					break;

				case IPCON_SRV_REMOVE:
					deal_srv_remove(handler, ike);
					break;
				default:
					break;
				}

				free(buf);
				continue;
			}

			if (srv_port) {
				if (src_port == srv_port) {
					ipcon_err("Server return : %s\n", buf);
					wait_response = 0;
					if (!strcmp(buf, "bye")) {
						ipcon_err("%s - %d: Quit...\n",
							__func__, __LINE__);
						free(buf);
						break;
					}
				}

				free(buf);
			}

			usleep(1000000);
		}

		ipcon_free_handler(handler);

	} while (0);

	exit(ret);

}
