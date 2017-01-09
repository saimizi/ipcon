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
	printf("[ipcon_cmd] %s-%d " fmt, __func__, __LINE__,  ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	printf("[ipcon_cmd] %s-%d "fmt, __func__, __LINE__, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	printf("[ipcon_cmd] %s-%d "fmt, __func__, __LINE__, ##__VA_ARGS__)

int main(int argc, char *argv[])
{
	int ret = 0;
	IPCON_HANDLER handler;

	do {
		__u32 srv_port;
		unsigned int group;
		char *msg = NULL;

		if (argc <= 1)
			break;

		msg = argv[1];

		/* Create client handler */
		handler = ipcon_create_handler();
		if (!handler) {
			ipcon_err("Failed to create libipcon handler.\n");
			break;
		}

		/* Find service */
		ret = ipcon_find_service(handler,
					"ipcon_server",
					&srv_port,
					&group);
		if (ret < 0) {
			ipcon_err("Failed to find service ipcon_server.\n");
		} else {
			ipcon_info(
				"service %s at port %lu (grp: %u).\n",
				"ipcon_server",
				(unsigned long)srv_port,
				group);

			/* Send message to server */
			ipcon_send_unicast(handler,
					srv_port,
					msg,
					strlen(msg) + 1);
		}

		/* Free client handler */
		ipcon_free_handler(handler);

	} while (0);

	exit(ret);

}
