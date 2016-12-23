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

int nltest_id = -1;

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

#if 1
		{
			struct nl_cache *ctrl = NULL;
			struct genl_family *family = NULL;

			ret = genl_ctrl_alloc_cache(nsk, &ctrl);
			if (ret) {
				nltest_error("Failed to alloc ctrl cache: %s\n",
					nl_geterror(ret));
				ret = -ENOMEM;
				break;
			}

			family = genl_ctrl_search_by_name(ctrl, "nltest");
			if (!family) {
				nltest_error("Failed to get protocol family\n");
				ret = -1;
				break;
			}

			nltest_id = genl_family_get_id(family);
			if (nltest_id == 0){
				nltest_error("Failed to get id.\n");
				ret = -1;
				break;
			}

		}
#endif
		

		nltest_info("port id: %d\n",nltest_id);



	} while (0);

	return ret;
}
