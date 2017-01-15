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
	printf("[ipcon_server] %s-%d " fmt, __func__, __LINE__,  ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	printf("[ipcon_server] %s-%d "fmt, __func__, __LINE__, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	printf("[ipcon_server] %s-%d "fmt, __func__, __LINE__, ##__VA_ARGS__)

static int do_mainloop(IPCON_HANDLER handler)
{
	int should_quit = 0;
	int ret = 0;

	while (!should_quit) {
		__u32 src_port = 0;
		char *buf = NULL;
		int len = 0;
		unsigned int group = 0;

		len = ipcon_rcv(handler, &src_port, &group, (void **) &buf);
		if (len < 0) {
			ipcon_err("Receive msg from failed\n");
			break;
		}

		ipcon_info("Msg from port %lu size= %d: %s\n",
			(unsigned long)src_port, len, buf);

		if (!strcmp(buf, "bye")) {
			ipcon_info("Quit...\n");
			free(buf);
			break;
		}

		ret = ipcon_send_unicast(handler,
					src_port,
					"OK",
					strlen("OK") + 1);

		ret = ipcon_send_multicast(handler, buf, strlen(buf) + 1);

		ipcon_info("Forward msg to group %u %s (%d)\n",
				ipcon_get_selfsrv(handler)->group,
				(ret < 0) ?  "failed" : "success",
				ret);

		if (!strcmp(buf, "byeall")) {
			ipcon_info("Quit...\n");
			free(buf);
			break;
		}

		free(buf);
	}

	return ret;
}

int main(int argc, char *argv[])
{
	int ret = 0;
	IPCON_HANDLER handler;
	unsigned int srv_group = IPCON_AUOTO_GROUP;
	struct ipcon_srv *srv = NULL;
	pid_t pid;

	do {

		/* Create server handler */
		handler = ipcon_create_handler();
		if (!handler) {
			ipcon_err("Failed to create libipcon handler.\n");
			return ret;
		}

		/* Register service */
		ipcon_dbg("Register %s.\n", argv[0]);
		ret = ipcon_register_service(handler, argv[0], srv_group);
		if (ret) {
			ipcon_err("Failed to register %s: %s (%d)\n",
					argv[0], strerror(-ret), ret);
			ipcon_free_handler(handler);
			return ret;
		}

		srv = ipcon_get_selfsrv(handler);
		if (!srv)
			break;

		ipcon_info("%s@%lu (group=%u) registered.\n",
				srv->name,
				(unsigned long)ipcon_get_selfport(handler),
				srv->group);

		pid = fork();
		if (pid)
			ret = do_mainloop(handler);
		else {
			char const *cmd = "/usr/bin/ipcon_multicast";
			char const *argv[] = {cmd, NULL};

			execve(cmd, argv, NULL);
		}

	} while (0);

	if (!srv)
		free(srv);

	/* Unregister service */
	ret = ipcon_unregister_service(handler);
	ipcon_dbg("Unregister %s %s.\n", argv[0], ret ? "failed":"success");

	/* Free handler */
	ipcon_free_handler(handler);

	exit(ret);

}
