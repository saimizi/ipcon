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

unsigned int srv_group;
__u32 srv_port;

static int deal_srv_add(IPCON_HANDLER handler,
		struct ipcon_kern_event *ike)
{
	int ret = 0;

	ipcon_info("Srv %s@%lu (grp: %u) added\n", ike->name,
			(unsigned long) ike->port, ike->group);

	if (!strcmp(ike->name, "ipcon_server") && !srv_group && !srv_port) {
		ret = ipcon_join_group(handler, ike->group);
		if (!ret) {
			srv_group = ike->group;
			srv_port = ike->port;
			ipcon_info("Success to join group %u of %s@%lu.\n",
					ike->group,
					ike->name,
					(unsigned long) ike->port);
		} else {
			ipcon_info("Failed to join group %u of %s@%lu.\n",
					ike->group,
					ike->name,
					(unsigned long) ike->port);
		}
	}

	return ret;
}

static int deal_srv_remove(IPCON_HANDLER handler,
			struct ipcon_kern_event *ike)
{
	int ret = 0;

	ipcon_info("Srv %s@%lu (grp: %u) removed\n",
		ike->name, (unsigned long) ike->port, ike->group);

	if (!strcmp(ike->name, "ipcon_server") && srv_group && srv_port) {
		ret = ipcon_leave_group(handler, srv_group);
		if (!ret) {
			srv_group = 0;
			srv_port = 0;
			ipcon_info("Success to leave group %u of %s@%lu.\n",
					ike->group,
					ike->name,
					(unsigned long) ike->port);
		} else {
			ipcon_info("Failed to leave group %u of %s@%lu.\n",
					ike->group,
					ike->name,
					(unsigned long) ike->port);
		}
	}

	return ret;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	IPCON_HANDLER handler;
	unsigned int should_quit = 0;

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
		if (!ret) {
			ret = ipcon_join_group(handler, srv_group);
			if (ret < 0) {
				ipcon_err("Failed to join group %d %s(%d).\n",
					srv_group,
					strerror(-ret),
					ret);
				ipcon_free_handler(handler);
				break;
			}
		}

		/* Wait client */
		while (!should_quit) {
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

			if (group == IPCON_MC_GROUP_KERN) {
				struct ipcon_kern_event *ike =
					(struct ipcon_kern_event *)buf;

				switch (ike->event) {
				case IPCON_SRV_ADD:
					ret = deal_srv_add(handler, ike);
					if (ret < 0)
						should_quit = 1;

					break;

				case IPCON_SRV_REMOVE:
					ret = deal_srv_remove(handler, ike);
					if (ret < 0)
						should_quit = 1;

					break;

				case IPCON_POINT_REMOVE:
					ipcon_info("Point %lu removed\n",
						(unsigned long) ike->port);

					if (ike->port == srv_port) {
						ipcon_info("Quit...\n");
						should_quit = 1;
					}
					break;

				default:
					ipcon_err("Unknown kernel event (%d).\n",
						ike->event);
				}
			}

			free(buf);
		}

		/* Free handler */
		ipcon_free_handler(handler);


	} while (0);

	exit(ret);

}
