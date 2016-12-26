#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <errno.h>

#include "libipcon_internal.h"

IPCON_HANDLER ipcon_create_handler(void)
{
	struct ipcon_mng_info *imi = NULL;

	do {
		int ret = 0;

		imi = (struct ipcon_mng_info *) malloc(sizeof(*imi));
		if (!imi)
			break;

		imi->sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_IPCON);
		if (imi->sk < 0) {
			libipcon_err("Failed to open netlink socket.\n");
			free(imi);
			imi = NULL;
			break;
		}

		imi->type = IPCON_TYPE_USER;
		imi->srv = NULL;

		imi->local.nl_family = AF_NETLINK;
		imi->local.nl_pid = NLPORT;
		imi->local.nl_groups = 0;

		ret = bind(imi->sk, (const struct sockaddr *) &(imi->local),
							sizeof(imi->local));
		if (ret < 0) {
			libipcon_err("Failed to bind netlink socket.\n");
			close(imi->sk);
			free(imi);
			imi = NULL;
			break;
		}

		/* FIXME: Get the port id auto binded by kernel*/
		libipcon_dbg("Port: %lu\n", (unsigned long)imi->local.nl_pid);
		ret = 0;

	} while (0);

	return (IPCON_HANDLER) imi;
}

void ipcon_free_handler(IPCON_HANDLER handler)
{
	struct ipcon_mng_info *imi = handler_to_info(handler);

	if (!imi)
		return;

	if (imi->type == IPCON_TYPE_SERVICE) {
		send_unicast_msg(imi->sk, 0, IPCON_POINT_UNREG,
					imi->srv, sizeof(*(imi->srv)));
		free(imi->srv);
	}

	close(imi->sk);
	free(imi);
}

int ipcon_register_service(IPCON_HANDLER handler, char *name)
{
	int ret = 0;
	struct ipcon_mng_info *imi = handler_to_info(handler);
	struct ipcon_point *srv = NULL;

	if (!imi || !name || !strlen(name))
		return -EINVAL;

	srv = (struct ipcon_point *) malloc(sizeof(*srv));
	if (!srv)
		return -ENOMEM;

	strcpy(srv->name, name),

	ret = send_unicast_msg(imi, 0, IPCON_POINT_REG, srv, sizeof(*srv));
	if (!ret) {
		imi->type = IPCON_TYPE_SERVICE;
		imi->srv = srv;
	}

	return ret;
}
