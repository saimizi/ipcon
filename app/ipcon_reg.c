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
	IPCON_HANDLER handler2;
	__u32 srv_port;

	do {
		handler2 = ipcon_create_handler();
		if (!handler2) {
			ipcon_err("Failed to create libipcon handler.\n");
			break;
		}

		handler = ipcon_create_handler();
		if (!handler) {
			ipcon_err("Failed to create libipcon handler.\n");
			ipcon_free_handler(handler);
			break;
		}

		ipcon_dbg("Register %s.\n", argv[1]);
		if (argc > 1) {
			ret = ipcon_register_service(handler, argv[1]);
			if (ret) {
				ipcon_err("Failed to register %s: %s (%d)\n",
					argv[1], strerror(-ret), ret);
				ipcon_free_handler(handler);
				ipcon_free_handler(handler2);
				break;
			}

			ipcon_err("%s registered.\n", argv[1]);
		} else {
			ipcon_err("No service name specified.\n");
			ipcon_free_handler(handler);
			ipcon_free_handler(handler2);
			break;
		}

		ret = ipcon_find_service(handler2, argv[1], &srv_port);
		if (ret < 0) {
			ipcon_err("Failed to find service %s.\n",
					argv[1]);
			ipcon_free_handler(handler);
			ipcon_free_handler(handler2);
			break;
		}

		{
			char *msg = "Hello world!";

			ipcon_info("service %s is at port %lu.\n",
					argv[1], (unsigned long)srv_port);

			ipcon_send_unicast_msg(handler2,
						srv_port,
						msg,
						strlen(msg) + 1);
		}

		{
			__u32 src_port = 0;
			char *buf = NULL;
			int len = 0;

			len = ipcon_rcv_msg(handler, &src_port, (void **) &buf);
			if (len < 0) {
				ipcon_err("Receive msg from handler2 failed\n");
				ipcon_free_handler(handler);
				ipcon_free_handler(handler2);
				break;
			}

			ipcon_info("Msg from port %lu size= %d: %s\n",
					(unsigned long)src_port, len, buf);
			free(buf);

		}

		ret = ipcon_unregister_service(handler);
		ipcon_dbg("Unregister %s %s.\n",
				argv[1],
				ret ? "failed":"success");

		ipcon_free_handler(handler);
		ipcon_free_handler(handler2);
	} while (0);

	exit(0);

}
