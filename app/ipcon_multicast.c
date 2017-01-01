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
	printf("[ipcon_mc] %s-%d " fmt, __func__, __LINE__,  ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	printf("[ipcon_mc] %s-%d "fmt, __func__, __LINE__, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	printf("[ipcon_mc] %s-%d "fmt, __func__, __LINE__, ##__VA_ARGS__)

int multicast_cb(__u32 port, unsigned int group, void *para)
{
	ipcon_info("Multicast msg: port= %lu, group=%u\n",
			(unsigned long)port, group);

	if (group == IPCON_MC_GROUP_KERN) {
		struct ipcon_kern_event *ike = para;

		ipcon_info("Srv %d is %s\n",
			(int) ike->port,
			(ike->event == IPCON_SRV_REMOVE) ?
					"Removed" : "Added");
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	IPCON_HANDLER handler;
	unsigned int srv_group;
	__u32 srv_port;

	do {
		/* Create server handler */
		handler = ipcon_create_handler();
		if (!handler) {
			ipcon_err("Failed to create libipcon handler.\n");
			break;
		}

		ret = ipcon_join_group(handler, IPCON_MC_GROUP_KERN);
		if (ret < 0) {
			ipcon_err("Failed to join group %d %s(%d).\n",
					IPCON_MC_GROUP_KERN,
					strerror(-ret),
					ret);
			ipcon_free_handler(handler);
			break;
		}

		/* Find service */
		ret = ipcon_find_service(handler,
					"ipcon_server",
					&srv_port,
					&srv_group);
		if (ret < 0) {
			ipcon_err("Failed to find service ipcon_server. %s(%d)\n",
					strerror(-ret), ret);
			ipcon_free_handler(handler);
			break;
		}

		ret = ipcon_join_group(handler, srv_group);
		if (ret < 0) {
			ipcon_err("Failed to join group %d %s(%d).\n",
					srv_group,
					strerror(-ret),
					ret);
			ipcon_free_handler(handler);
			break;
		}

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

			if (group == srv_group) {
				ipcon_info("Multicast msg from %u@%u :%s\n",
						srv_group,
						src_port,
						buf);
				free(buf);
				continue;
			}

			multicast_cb(src_port, group, buf);
			free(buf);
		}

		/* Free handler */
		ipcon_free_handler(handler);


	} while (0);

	exit(ret);

}
