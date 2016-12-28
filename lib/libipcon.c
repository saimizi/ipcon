#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>

#include "libipcon_internal.h"

IPCON_HANDLER ipcon_create_handler(
	int (*multicast_cb)(__u32 port,
			unsigned int group,
			void *para))
{
	struct ipcon_mng_info *imi = NULL;
	int ret = 0;

	do {
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
		imi->multicast_cb = multicast_cb;

		ret = bind(imi->sk, (const struct sockaddr *) &(imi->local),
							sizeof(imi->local));
		if (ret < 0) {
			libipcon_err("Failed to bind netlink socket.\n");
			break;
		}

		ret = send_unicast_msg(imi,
					0,
					NLM_F_ACK | NLM_F_REQUEST,
					IPCON_GET_SELFID,
					NULL,
					1);

		if (!ret) {
			struct nlmsghdr *nlh = NULL;

			/* FIXME: Add timeout here */
			while (1) {
				ret = rcv_unicast_msg(imi, 0, &nlh);
				if (ret)
					break;

				if (nlh->nlmsg_type == NLMSG_ERROR) {
					struct nlmsgerr *nlerr;

					nlerr = NLMSG_DATA(nlh);
					ret = nlerr->error;
					free(nlh);
					break;
				}

				imi->local.nl_pid = *(__u32 *)NLMSG_DATA(nlh);
			}
		}

		libipcon_dbg("Port: %lu\n", (unsigned long)imi->local.nl_pid);

	} while (0);

	if (ret < 0) {
		close(imi->sk);
		if (imi)
			free(imi);
		imi = NULL;
	}

	return (IPCON_HANDLER) imi;
}

void ipcon_free_handler(IPCON_HANDLER handler)
{
	struct ipcon_mng_info *imi = handler_to_info(handler);

	if (!imi)
		return;

	if (imi->type == IPCON_TYPE_SERVICE) {
		int ret = 0;


		ret = send_unicast_msg(imi,
					0,
					NLM_F_ACK | NLM_F_REQUEST,
					IPCON_SRV_UNREG,
					imi->srv,
					sizeof(*(imi->srv)));

		if (!ret) {
			ret = wait_err_response(imi, 0, IPCON_SRV_UNREG);
			libipcon_dbg("Unregister %s by free handler %s.\n",
					imi->srv->name,
					ret ? "failed":"success");
		}

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

	ret = send_unicast_msg(imi,
				0,
				NLM_F_ACK | NLM_F_REQUEST,
				IPCON_SRV_REG,
				srv,
				sizeof(*srv));
	if (!ret) {
		ret = wait_err_response(imi, 0, IPCON_SRV_REG);
		if (!ret) {
			imi->type = IPCON_TYPE_SERVICE;
			imi->srv = srv;
		}
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

	ret = send_unicast_msg(imi,
			0,
			NLM_F_ACK | NLM_F_REQUEST,
			IPCON_SRV_UNREG,
			imi->srv,
			sizeof(*(imi->srv)));
	if (!ret) {
		ret = wait_err_response(imi, 0, IPCON_SRV_UNREG);

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

int ipcon_find_service(IPCON_HANDLER handler, char *name, __u32 *srv_port)
{
	int ret = 0;
	struct ipcon_mng_info *imi = handler_to_info(handler);

	if (!imi || !name || !srv_port)
		return -EINVAL;

	ret = send_unicast_msg(imi,
			0,
			NLM_F_ACK | NLM_F_REQUEST,
			IPCON_SRV_RESLOVE,
			name,
			strlen(name) + 1);

	if (!ret) {
		struct nlmsghdr *nlh = NULL;

		/* FIXME: Add timeout here */
		while (1) {
			ret = rcv_unicast_msg(imi, 0, &nlh);
			if (ret)
				break;

			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *nlerr;

				nlerr = NLMSG_DATA(nlh);
				ret = nlerr->error;
				free(nlh);
				break;
			}

			*srv_port = *(__u32 *)NLMSG_DATA(nlh);
		}
	}

	return ret;
}

int ipcon_rcv_msg(IPCON_HANDLER handler, __u32 *port, void **buf)
{
	int ret = 0;
	struct nlmsghdr *nlh = NULL;
	struct ipcon_mng_info *imi = handler_to_info(handler);
	int data_size = 0;

	if (!imi)
		return -EINVAL;

	while (1) {
		ret = rcv_unicast_msg(imi, 0, &nlh);
		if (!ret) {
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *nlerr;

				nlerr = NLMSG_DATA(nlh);
				ret = nlerr->error;
				free(nlh);

				break;

			} else if (nlh->nlmsg_type == IPCON_MULICAST_EVENT) {
				char *para = NLMSG_DATA(nlh);
				unsigned int group = 0;

				if (imi->multicast_cb) {
					memcpy(&group, para, sizeof(group));
					ret = imi->multicast_cb(
						nlh->nlmsg_pid,
						group,
						(void *)(para + sizeof(group)));
				}

				free(nlh);

			} else {
				char *tmp_buf = NULL;

				data_size = (int)(nlh->nlmsg_len -
						NLMSG_HDRLEN);
				tmp_buf = (char *)malloc((size_t)data_size);
				memcpy(tmp_buf, NLMSG_DATA(nlh),
						(size_t)data_size);
				*buf = tmp_buf;
				ret = data_size;
				*port = nlh->nlmsg_pid;
				free(nlh);

				break;
			}

		}
	}

	return ret;
}

int ipcon_send_unicast_msg(IPCON_HANDLER handler, __u32 port,
					void *buf, size_t size)
{
	int ret = 0;
	struct nlmsghdr *nlh = NULL;
	struct ipcon_mng_info *imi = handler_to_info(handler);
	int data_size = 0;

	if (!imi || !port)
		return -EINVAL;

	ret = send_unicast_msg(imi,
			port,
			NLM_F_REQUEST,
			IPCON_USER,
			buf,
			size);


	return ret;
}

int ipcon_join_group(IPCON_HANDLER handler, unsigned int group)
{
	int ret = 0;
	struct ipcon_mng_info *imi = handler_to_info(handler);

	if (!imi || !group)
		return -EINVAL;

	ret = setsockopt(imi->sk,
			SOL_NETLINK,
			NETLINK_ADD_MEMBERSHIP,
			&group,
			sizeof(group));
	if (ret == -1)
		ret = -errno;
	else
		ret = 0;

	return ret;

}
