#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <errno.h>

#include "libipcon.h"
#include "libipcon_internal.h"

IPCON_HANDLER ipcon_create_handler(void)
{
	struct ipcon_mng_info *imi = NULL;
	struct sockaddr_nl local;
	int ret = 0;

	do {
		imi = (struct ipcon_mng_info *) malloc(sizeof(*imi));
		if (!imi)
			break;

		memset(imi, 0, sizeof(*imi));
		imi->sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_IPCON);
		if (imi->sk < 0) {
			libipcon_err("Failed to open netlink socket.\n");
			free(imi);
			imi = NULL;
			break;
		}

		imi->type = IPCON_TYPE_USER;

		local.nl_family = AF_NETLINK;
		local.nl_pid = NLPORT;
		local.nl_groups = 0;

		ret = bind(imi->sk, (const struct sockaddr *) &local,
						sizeof(local));
		if (ret < 0) {
			libipcon_err("Failed to bind netlink socket.\n");
			break;
		}

		ret = send_unicast_msg(imi,
					0,
					NLM_F_ACK | NLM_F_REQUEST,
					IPCON_GET_SELFID,
					NULL,
					0);

		if (!ret) {
			struct nlmsghdr *nlh = NULL;
			struct sockaddr_nl from;
			struct ipcon_msghdr *im = NULL;

			/* FIXME: Add timeout here */
			while (1) {
				ret = rcv_msg(imi, &from, &nlh,
					max_size_nlerr(IPCONMSG_SPACE(0)));
				if (ret < 0)
					break;

				if (nlh->nlmsg_type == NLMSG_ERROR) {
					struct nlmsgerr *nlerr;

					nlerr = NLMSG_DATA(nlh);
					ret = nlerr->error;
					free(nlh);
					break;
				}

				if (nlh->nlmsg_type == IPCON_GET_SELFID) {
					im = NLMSG_DATA(nlh);
					imi->port = im->selfid;
					free(nlh);
					continue;
				}

				/*
				 * Do not queue msg, there is impossible
				 * to receive a meaningful msg here
				 */
				libipcon_err("Unexpected nlmsg.(type = %d)\n",
						nlh->nlmsg_type);
				free(nlh);
			}
		}

		libipcon_dbg("Port: %lu\n", (unsigned long)imi->port);

	} while (0);

	if (ret < 0) {
		close(imi->sk);
		if (imi)
			free(imi);
		imi = NULL;
	}

	return (IPCON_HANDLER) imi;
}

int ipcon_free_handler(IPCON_HANDLER handler)
{
	struct ipcon_mng_info *imi = handler_to_info(handler);
	struct ipcon_msghdr *im = NULL;
	int ret = 0;

	if (!imi)
		return;

	do {
		if (imi->type == IPCON_TYPE_SERVICE)
			ret = ipcon_unregister_service(handler);

		if (!ret)
			free(imi);
	} while (0);

	return ret;
}

int ipcon_register_service(IPCON_HANDLER handler, char *name,
				unsigned int group)
{
	int ret = 0;
	struct ipcon_mng_info *imi = handler_to_info(handler);
	struct ipcon_srv *srv = NULL;
	struct ipcon_msghdr *im = NULL;

	if (!imi || !name || !strlen(name) ||
		(strlen(name) > IPCON_MAX_SRV_NAME_LEN - 1))
		return -EINVAL;

	if ((group > IPCON_AUOTO_GROUP) || (group == IPCON_MC_GROUP_KERN))
		return -EINVAL;


	im = alloc_ipconmsg(sizeof(struct ipcon_srv));
	if (!im)
		return -ENOMEM;

	srv = IPCONMSG_DATA(im);
	strcpy(srv->name, name);

	srv->group = group;

	ret = send_unicast_msg(imi,
				0,
				NLM_F_ACK | NLM_F_REQUEST,
				IPCON_SRV_REG,
				im,
				im->ipconmsg_len);

	free(im);

	if (!ret) {
		struct nlmsgerr *nlerr;
		struct nlmsghdr *nlh = NULL;
		struct sockaddr_nl from;

		do {
			/* FIXME: Add caching function */
			ret = rcv_msg(imi, &from, &nlh,
				max_size_nlerr(IPCONMSG_SPACE(0)));

			if (ret)
				break;

			if (nlh->nlmsg_type == NLMSG_ERROR) {
				nlerr = NLMSG_DATA(nlh);
				if (nlerr->msg.nlmsg_type !=
					IPCON_SRV_REG) {
					libipcon_err(
						"Unexpected msg.(type = %d)\n",
						nlh->nlmsg_type);
					free(nlh);
					continue;
				}

				ret = nlerr->error;
				free(nlh);
				break;
			}

			if (nlh->nlmsg_type == IPCON_SRV_REG) {
				im = NLMSG_DATA(nlh);
				imi->srv.group = im->group;
				strcpy(imi->srv.name, name);
				imi->type = IPCON_TYPE_SERVICE;
				free(nlh);
				continue;
			}

			if (queue_msg(imi, nlh, &from))
				libipcon_warn("Received msg maybe lost.\n");


		} while (1);
	}

	libipcon_dbg("Register %s@%lu (group: %u) %s.\n",
			name,
			(unsigned long)imi->port,
			imi->srv.group,
			ret ? "failed":"success");

	return ret;
}

int ipcon_unregister_service(IPCON_HANDLER handler)
{
	int ret = 0;

	struct ipcon_mng_info *imi = handler_to_info(handler);
	struct ipcon_msghdr *im = NULL;
	struct ipcon_srv *srv = NULL;

	do {
		if (!imi) {
			ret = -EINVAL;
			break;
		}

		if (imi->type != IPCON_TYPE_SERVICE) {
			ret = -EINVAL;
			break;
		}

		im = alloc_ipconmsg(sizeof(struct ipcon_srv));
		if (!im) {
			ret = -ENOMEM;
			break;
		}

		srv = IPCONMSG_DATA(im);
		memcpy(srv, &imi->srv, sizeof(struct ipcon_srv));

		ret = send_unicast_msg(imi,
				0,
				NLM_F_ACK | NLM_F_REQUEST,
				IPCON_SRV_UNREG,
				im,
				im->ipconmsg_len);
		if (ret < 0)
			break;

		ret = wait_err_response(imi, 0, IPCON_SRV_UNREG);
		if (!ret) {

			libipcon_dbg("Unregister %s success.\n",
					imi->srv.name);

			memset(&imi->srv, 0, sizeof(struct ipcon_srv));
			imi->type = IPCON_TYPE_USER;
		} else {
			libipcon_dbg("Unregister %s failed (%d).\n",
					imi->srv.name, ret);
		}

	} while (0);

	return ret;
}

int ipcon_find_service(IPCON_HANDLER handler, char *name, __u32 *srv_port,
		unsigned int *group)
{
	int ret = 0;
	struct ipcon_mng_info *imi = handler_to_info(handler);
	struct ipcon_msghdr *im = NULL;
	char *srv_name = NULL;

	do {
		if (!imi || !srv_port || !group) {
			ret = -EINVAL;
			break;
		}

		if (!name || !strlen(name) ||
			(strlen(name) > IPCON_MAX_SRV_NAME_LEN - 1)) {
			ret = -EINVAL;
			break;
		}

		im = alloc_ipconmsg(strlen(name) + 1);
		if (!im) {
			ret = -ENOMEM;
			break;
		}

		srv_name = IPCONMSG_DATA(im);
		strcpy(srv_name, name);
		ret = send_unicast_msg(imi,
				0,
				NLM_F_ACK | NLM_F_REQUEST,
				IPCON_SRV_RESLOVE,
				im,
				im->ipconmsg_len);
		free(im);
		if (ret < 0)
			break;


		do {
			struct nlmsghdr *nlh = NULL;
			struct nlmsgerr *nlerr = NULL;
			struct sockaddr_nl from;

			memset(&from, 0, sizeof(from));
			ret = rcv_msg(imi, &from, &nlh,
					max_size_nlerr(IPCONMSG_SPACE(0)));
			if (ret < 0)
				break;

			if (nlh->nlmsg_type == NLMSG_ERROR) {
				nlerr = NLMSG_DATA(nlh);

				ret = nlerr->error;
				free(nlh);
				break;
			}

			if (nlh->nlmsg_type == IPCON_SRV_RESLOVE) {
				im = NLMSG_DATA(nlh);
				*group = im->srv.group;
				*srv_port = im->srv.port;
				free(nlh);
				continue;
			}

			if (queue_msg(imi, nlh, &from))
				libipcon_warn("Received msg maybe lost.\n");

		} while (1);

	} while (0);

	return ret;
}

int ipcon_rcv(IPCON_HANDLER handler, __u32 *port,
		unsigned int *group, void **buf, __u32 max_msg_size_hint)
{
	int ret = 0;
	struct nlmsghdr *nlh = NULL;
	struct ipcon_mng_info *imi = handler_to_info(handler);
	struct ipcon_msghdr *im = NULL;
	unsigned int t_group = 0;
	unsigned int t_port = 0;

	if (!imi)
		return -EINVAL;

	do {
		char *tmp_buf = NULL;

		if (imi->msg_queue) {
			struct ipcon_msg_link *iml = NULL;

			iml = dequeue_msg(imi);
			nlh = iml->nlh;
			t_group = get_group(iml->from.nl_groups);
			t_port = iml->from.nl_pid;
			iml->nlh = NULL;
			free_ipcon_msg_link(iml);
		} else {
			struct sockaddr_nl from;

			memset(&from, 0, sizeof(from));
			ret = rcv_msg(imi, &from, &nlh, max_msg_size_hint);

			t_group = get_group(from.nl_groups);
			t_port = from.nl_pid;
		}

		if (!ret) {
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				free(nlh);
				libipcon_err("Unexpected nlmsg_err msg.\n");
				continue;

			}

			im = NLMSG_DATA(nlh);
			if (im->size > 0) {
				tmp_buf = (char *)
					malloc((size_t)im->size);

				if (!tmp_buf) {
					ret = -ENOMEM;
					free(nlh);
					break;
				}

				memcpy(tmp_buf, IPCONMSG_DATA(im),
						(size_t)im->size);
			}

			*buf = tmp_buf;
			if (nlh->nlmsg_type == IPCON_MULICAST_EVENT)
				*port = im->rport;
			else
				*port = t_port;
			*group = t_group;
			ret = (int)im->size;
		}

		break;

	} while (1);

	return ret;
}

int ipcon_send_unicast(IPCON_HANDLER handler, __u32 port,
				void *buf, size_t size)
{
	int ret = 0;
	struct ipcon_mng_info *imi = handler_to_info(handler);
	struct ipcon_msghdr *im = NULL;

	if (!imi || !port || !buf || !size)
		return -EINVAL;

	im = alloc_ipconmsg(size);
	if (!im)
		return -ENOMEM;

	memcpy(IPCONMSG_DATA(im), buf, size);

	return send_unicast_msg(imi,
			port,
			NLM_F_REQUEST,
			IPCON_USER,
			im,
			im->ipconmsg_len);

}

int ipcon_send_multicast(IPCON_HANDLER handler, void *buf, size_t size)
{
	int ret = 0;
	struct ipcon_mng_info *imi = handler_to_info(handler);
	struct ipcon_msghdr *im = NULL;

	if (!imi || !buf || !size ||
		(imi->type != IPCON_TYPE_SERVICE) || !imi->srv.group)
		return -EINVAL;

	im = alloc_ipconmsg(size);
	if (!im)
		return -ENOMEM;

	im->rport = imi->port;
	im->size = (__u32)size;
	im->ipconmsg_len = IPCONMSG_SPACE(size);

	memcpy(IPCONMSG_DATA(im), buf, size);

	ret = send_unicast_msg(imi,
			0,
			NLM_F_REQUEST | NLM_F_ACK,
			IPCON_MULICAST_EVENT,
			im,
			im->ipconmsg_len);

	free(im);

	if (!ret) {
		struct nlmsgerr *nlerr;
		struct nlmsghdr *nlh = NULL;
		struct sockaddr_nl from;

		do {
			/* FIXME: Add caching function */
			ret = rcv_msg(imi, &from, &nlh, sizeof(*nlerr));
			if (ret)
				break;

			if (nlh->nlmsg_type != NLMSG_ERROR) {
				if (queue_msg(imi, nlh, &from))
					libipcon_warn("Received msg maybe lost.\n");
				continue;
			}

			nlerr = NLMSG_DATA(nlh);
			if (nlerr->msg.nlmsg_type != IPCON_MULICAST_EVENT) {
				libipcon_err("Unexpected msg.(type = %d)\n",
						nlh->nlmsg_type);
				free(nlh);
				continue;
			}

			ret = nlerr->error;
			free(nlh);
			break;

		} while (1);
	}

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

__u32 ipcon_get_selfport(IPCON_HANDLER handler)
{
	struct ipcon_mng_info *imi = handler_to_info(handler);

	return imi->port;
}

const struct ipcon_srv *ipcon_get_selfsrv(IPCON_HANDLER handler)
{
	struct ipcon_mng_info *imi = handler_to_info(handler);

	return (const struct ipcon_srv *) &imi->srv;
}
