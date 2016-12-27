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

#define ipcon_dbg(fmt, ...)	printf("[ipcon_reg] "fmt, ##__VA_ARGS__)
#define ipcon_info(fmt, ...)	printf("[ipcon_reg] "fmt, ##__VA_ARGS__)
#define ipcon_err(fmt, ...)	printf("[ipcon_reg] "fmt, ##__VA_ARGS__)

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

		ipcon_dbg("Register %s.\n", argv[1]);
		if (argc > 1) {
			ret = ipcon_register_service(handler, argv[1]);
			if (ret)
				ipcon_err("Failed to register %s: %s (%d)\n",
					argv[1], strerror(-ret), ret);
			else
				ipcon_err("%s registered.\n", argv[1]);
		} else {
			ipcon_err("No service name specified.\n");
		}

#if 1
		ret = ipcon_unregister_service(handler);
		ipcon_dbg("Unregister %s %s.\n",
				argv[1],
				ret ? "failed":"success");
#endif

		ipcon_free_handler(handler);
	} while (0);

	exit(0);

}
