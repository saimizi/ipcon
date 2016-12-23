#include <linux/kernel.h>
#include <linux/module.h>

#include <net/sock.h>
#include <net/netlink.h>
#include "ipcon.h"
#include "ipcon_nl.h"
#include "ipcon_dbg.h"

#define SRV_TABLE_SIZE	1024
static struct srv_info *srv_mng[SRV_TABLE_SIZE];


static int ipcon_init(void)
{
	int ret = 0;
	int i;

	ret = ipcon_nl_init();
	if (!ret) {
		for (i = 0; i < SRV_TABLE_SIZE; i++)
			srv_mng[i] = NULL;
	}

	if (ret)
		ipcon_info("init failed (%d).\n", ret);
	else
		ipcon_info("init successfully.\n");

	return ret;
}

static void ipcon_exit(void)
{
	ipcon_info("exit.\n");
	ipcon_nl_exit();
}

module_init(ipcon_init);
module_exit(ipcon_exit);

MODULE_DESCRIPTION("IPC Over Netlink(IPCON) Driver");
MODULE_LICENSE("GPL");
