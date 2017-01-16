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
	printf("[ipcon_server] %s-%d " fmt, __func__, __LINE__,  ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	printf("[ipcon_server] %s-%d "fmt, __func__, __LINE__, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	printf("[ipcon_server] %s-%d "fmt, __func__, __LINE__, ##__VA_ARGS__)

__u32 sender_port;


static int do_mainloop(IPCON_HANDLER handler)
{
	int should_quit = 0;
	int ret = 0;

	while (!should_quit) {
		__u32 src_port = 0;
		char *buf = NULL;
		int len = 0;
		unsigned int group = 0;

		len = ipcon_rcv(handler, &src_port, &group, (void **) &buf);
		if (len < 0) {
			ret = len;
			ipcon_err("Receive msg from failed\n");
			break;
		}

		if (group == IPCON_MC_GROUP_KERN) {
#ifdef SERVER_AUTO_RESTART
			pid_t pid;
			char const *cmd = "/usr/bin/ipcon_sender";
			char const *argv[] = {cmd, "Hello", NULL};
#endif

			if (sender_port) {
				struct ipcon_kern_event *ike =
					(struct ipcon_kern_event *)buf;

				if ((ike->event == IPCON_POINT_REMOVE) &&
					(ike->port == sender_port)) {
					sender_port = 0;

#ifdef SERVER_AUTO_RESTART
					ipcon_err("ipcon sender is sadly lost. restart it\n");
					pid = fork();
					if (!pid)
						execve(cmd, argv, NULL);
#else
					ipcon_err("ipcon sender is sadly lost...\n");
#endif
				}
			}

			free(buf);
			continue;
		}

		/*
		 * The first person who sends a message is regards as
		 * "ipcon_sender".
		 */
		if (!sender_port)
			sender_port = src_port;

		ipcon_info("Msg from port %lu size= %d: %s\n",
			(unsigned long)src_port, len, buf);

		ret = ipcon_send_unicast(handler, src_port,
				"OK", strlen("OK") + 1);

		ipcon_info("Forward msg to group %u\n",
			ipcon_get_selfsrv(handler)->group);

		ret = ipcon_send_multicast(handler, buf, strlen(buf) + 1);

		if (ret < 0) {
			ipcon_err("Forward msg to group %u failed.\n",
				ipcon_get_selfsrv(handler)->group);
		}

		if (!strcmp(buf, "bye")) {
			ipcon_info("Quit...\n");
			should_quit = 1;

			/* Stop ipcon_sender */
			if (sender_port)
				ret = ipcon_send_unicast(handler, sender_port,
						"bye", strlen("bye") + 1);
		}

		free(buf);
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

#define ipcon_service	"ipcon_server"

int main(int argc, char *argv[])
{
	int ret = 0;
	IPCON_HANDLER handler;
	struct ipcon_srv *srv = NULL;

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

	/* Create server handler */
	handler = ipcon_create_handler();
	if (!handler) {
		ipcon_err("Failed to create libipcon handler.\n");
		return ret;
	}

	do {
		/* Register service */
		ipcon_dbg("Register %s.\n", ipcon_service);
		ret = ipcon_register_service(handler,
				ipcon_service, IPCON_AUOTO_GROUP);
		if (ret) {
			ipcon_err("Failed to register %s: %s (%d)\n",
					ipcon_service, strerror(-ret), ret);
			ipcon_free_handler(handler);
			return ret;
		}

		srv = ipcon_get_selfsrv(handler);
		if (!srv)
			break;

		ipcon_info("%s@%lu (group=%u) registered.\n",
				srv->name,
				(unsigned long)ipcon_get_selfport(handler),
				srv->group);

		ret = ipcon_join_group(handler, IPCON_MC_GROUP_KERN);
		if (ret < 0) {
			ipcon_err("Failed to join group %d %s(%d).\n",
					IPCON_MC_GROUP_KERN,
					strerror(-ret),
					ret);
			break;
		}

		ret = do_mainloop(handler);


	} while (0);

	if (!srv)
		free(srv);

	/* Unregister service */
	ret = ipcon_unregister_service(handler);
	ipcon_dbg("Unregister %s %s.\n", argv[0], ret ? "failed":"success");

	/* Free handler */
	ipcon_free_handler(handler);

	exit(ret);

}
