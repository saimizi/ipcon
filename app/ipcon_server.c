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
	printf("[ipcon_server] %s-%d " fmt, __func__, __LINE__,  ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	printf("[ipcon_server] %s-%d "fmt, __func__, __LINE__, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	printf("[ipcon_server] %s-%d "fmt, __func__, __LINE__, ##__VA_ARGS__)

int main(int argc, char *argv[])
{
	int ret = 0;
	IPCON_HANDLER handler;
	unsigned int srv_group = IPCON_AUOTO_GROUP;

	do {
		/* Create server handler */
		handler = ipcon_create_handler();
		if (!handler) {
			ipcon_err("Failed to create libipcon handler.\n");
			break;
		}

		/* Register service */
		ipcon_dbg("Register %s.\n", argv[0]);
		ret = ipcon_register_service(handler, argv[0], &srv_group);
		if (ret) {
			ipcon_err("Failed to register %s: %s (%d)\n",
					argv[0], strerror(-ret), ret);
			ipcon_free_handler(handler);
			break;
		}

			ipcon_info("%s registered with group %d.\n",
					argv[0], srv_group);

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

			if (!strcmp(buf, "bye")) {
				free(buf);
				break;
			}

			ret = ipcon_send_multicast(handler,
					srv_group,
					buf,
					strlen(buf) + 1);

			ipcon_info("Forward msg to group %u %s (%d)\n",
					srv_group,
					(ret < 0) ?  "failed" : "success",
					ret);
			free(buf);
		}



	} while (0);

	/* Unregister service */
	ret = ipcon_unregister_service(handler);
	ipcon_dbg("Unregister %s %s.\n", argv[0], ret ? "failed":"success");

	/* Free handler */
	ipcon_free_handler(handler);

	exit(ret);

}
