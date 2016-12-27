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
		int ret = 0;

		send_unicast_msg(imi, 0, IPCON_POINT_UNREG,
					imi->srv, sizeof(*(imi->srv)));

		ret = wait_err_response(imi, 0, IPCON_POINT_UNREG);
		libipcon_dbg("Unregister %s by free handler %s.\n",
					imi->srv->name,
					ret ? "failed":"success");

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
	struct nlmsgerr nlerr;

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
		ret = wait_err_response(imi, 0, IPCON_POINT_REG);
	}

	libipcon_dbg("Register %s %s.\n", name, ret ? "failed":"success");

	return ret;
}

int ipcon_unregister_service(IPCON_HANDLER handler)
{
	int ret = 0;

	struct ipcon_mng_info *imi = handler_to_info(handler);

	if (!imi)
		return -EINVAL;

	if ((imi->type != IPCON_TYPE_SERVICE) || (!imi->srv))
		return -EINVAL;

	ret = send_unicast_msg(imi, 0, IPCON_POINT_UNREG,
				imi->srv, sizeof(*(imi->srv)));
	if (!ret) {
		ret = wait_err_response(imi, 0, IPCON_POINT_UNREG);

		libipcon_dbg("Unregister %s %s.\n",
					imi->srv->name,
					ret ? "failed":"success");
		if (!ret) {
			free(imi->srv);
			imi->srv = NULL;
			imi->type = IPCON_TYPE_USER;
		}
	} else {
		libipcon_err("Unregister failed(%d).\n", ret);
	}

	return ret;
}

int ipcon_find_service(IPCON_HANDLER handler, char *name)
{
	int ret = 0;
	struct nlmsghdr *nlh = NULL;

	struct ipcon_mng_info *imi = handler_to_info(handler);

	if (!imi || !name)
		return -EINVAL;

	ret = send_unicast_msg(imi, 0, IPCON_POINT_RESLOVE,
				name, strlen(name) + 1);

	if (!ret) {
		ret = rcv_unicast_msg(imi, 0, &nlh);
		if (!ret) {
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *nlerr;

				nlerr = NLMSG_DATA(nlh);
				ret = nlerr->error;
				free(nlh);
			} else {
				ret = *((int *)NLMSG_DATA(nlh));
			}
		}
	}

	return ret;
}
