#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/mngt.h>

#define nltest_debug(fmt,...)	printf("[nltest] %s - %d DEBUG:"fmt, \
					__func__,__LINE__,	\
					##__VA_ARGS__)

#define nltest_info(fmt,...)	printf("[nltest] %s - %d INFO:"fmt, \
					__func__,__LINE__,	\
					##__VA_ARGS__)

#define nltest_error(fmt,...)	printf("[nltest] %s - %d ERROR:"fmt, \
					__func__,__LINE__,	\
					##__VA_ARGS__)

#define		NLTEST_DUMP	1

#define ARRAY_SIZE(a)	(sizeof(a)/sizeof(a[0]))

static int nltest_msg_parser(struct nl_cache_ops *ops,
				struct genl_cmd *cmd,
				struct genl_info *info,
				void * data)
{
	return 0;
}

static struct nla_policy nltest_policy =
{
	.type	= NLA_UNSPEC,
	.minlen	= 0,
	.maxlen	= 1024,
};

static struct genl_cmd nltest_cmds[] =
{
	{
		.c_id		= NLTEST_DUMP,
		.c_name		= "nltest_dump",
		.c_maxattr	= 0,
		.c_attr_policy	= &nltest_policy,
		.c_msg_parser	= nltest_msg_parser,
	},
};

struct nltest_hdr
{
	int	i;
};

static struct genl_ops nltest_genl_ops = {
	.o_name		= "nltest",
	.o_hdrsize	= sizeof(struct nltest_hdr),
	.o_cmds		= nltest_cmds,
	.o_ncmds	= ARRAY_SIZE(nltest_cmds),
};

int main(int argc, char *argv[])
{
	struct nl_sock *nsk = NULL;
	int ret = 0;

	do {
		nsk = nl_socket_alloc();
		if (!nsk){
			nltest_error("Failed to alloc socket.\n");
			ret = -ENOMEM;
			break;
		}

		nl_socket_set_buffer_size(nsk, 8192, 8192);

		ret = genl_connect(nsk);
		if (ret) {
			nltest_error("Failed to connect genl socket: %s\n",
				nl_geterror(ret));
			ret = -ENOLINK;
			break;
		}

		ret = genl_register_family(&nltest_genl_ops);
		if (ret) {
			nltest_error("Failed to register family: %s\n",
				nl_geterror(ret));
			ret = -1;
			break;
		}

		/* Default callback handler cb_def will be called */
		ret = nl_recvmsgs_default(nsk);
		if (ret) {
			nltest_error("Failed to receive msgs: %s\n",
				nl_geterror(ret));
			ret = -1;
			break;
		}

		nl_socket_free(nsk);

	} while (0);

	return ret;
}
