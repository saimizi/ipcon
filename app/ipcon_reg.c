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

#include "ipcon.h"
#include "libipcon.h"

#define ipcon_dbg(fmt, ...) \
	printf("[ipcon_reg] %s-%d " fmt, __func__, __LINE__,  ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	printf("[ipcon_reg] %s-%d "fmt, __func__, __LINE__, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	printf("[ipcon_reg] %s-%d "fmt, __func__, __LINE__, ##__VA_ARGS__)

int main(int argc, char *argv[])
{
	int ret = 0;
	IPCON_HANDLER handler;
	pid_t pid;

	do {
		/* Create server handler */
		handler = ipcon_create_handler();
		if (!handler) {
			ipcon_err("Failed to create libipcon handler.\n");
			break;
		}

		/* Register service */
		ipcon_dbg("Register %s.\n", argv[1]);
		if (argc > 1) {
			ret = ipcon_register_service(handler, argv[1]);
			if (ret) {
				ipcon_err("Failed to register %s: %s (%d)\n",
					argv[1], strerror(-ret), ret);
				ipcon_free_handler(handler);
				break;
			}

			ipcon_info("%s registered.\n", argv[1]);
		} else {
			ipcon_err("No service name specified.\n");
			ipcon_free_handler(handler);
			ret = -1;
			break;
		}

		pid = fork();
		if (pid) {
			/* Wait client */
			while (1) {
				__u32 src_port = 0;
				char *buf = NULL;
				int len = 0;
				unsigned int group = 0;

				len = ipcon_rcv(handler,
						&src_port,
						&group,
						(void **) &buf,
						0);

				if (len < 0) {
					ipcon_err("Receive msg from failed\n");
					ipcon_free_handler(handler);
					break;
				}

				ipcon_info("Msg from port %lu size= %d: %s\n",
					(unsigned long)src_port, len, buf);
				free(buf);
				break;
			}

			/* Unregister service */
			ret = ipcon_unregister_service(handler);
			ipcon_dbg("Unregister %s %s.\n",
					argv[1],
					ret ? "failed":"success");

			/* Free handler */
			ipcon_free_handler(handler);

		} else {
			IPCON_HANDLER handler2;
			__u32 srv_port;
			char *msg = "Hello world!";

			/* Create client handler */
			handler2 = ipcon_create_handler();
			if (!handler2) {
				ipcon_err("Failed to create libipcon handler.\n");
				break;
			}

			/* Find service */
			ret = ipcon_find_service(handler2, argv[1], &srv_port);
			if (ret < 0) {
				ipcon_err("Failed to find service %s.\n",
						argv[1]);
			} else {
				ipcon_info("service %s is at port %lu.\n",
					argv[1], (unsigned long)srv_port);

				/* Send message to server */
				ipcon_send_unicast(handler2,
						srv_port,
						msg,
						strlen(msg) + 1);
			}

			/* Free client handler */
			ipcon_free_handler(handler2);
		}

	} while (0);

	exit(ret);

}
