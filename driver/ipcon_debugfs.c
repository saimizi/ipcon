/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <linux/debugfs.h>
#include <linux/slab.h>

#include "ipcon_tree.h"
#include "ipcon_nl.h"
#include "ipcon_dbg.h"

struct dentry *diret;
struct dentry *grp_bit_flag;
struct dentry *service;

static ssize_t srv_file_read(struct file *fp, char __user *user_buffer,
				size_t count, loff_t *position)
{
	char *buf = NULL;
	char *p = NULL;
	struct ipcon_msghdr **rim = file_inode(fp)->i_private;
	struct ipcon_tree_node *nd = NULL;
	ssize_t ret = 0;

	ipcon_lock();
	nd = ipcon_lookup_unlock(fp->f_path.dentry->d_iname);
	if (!nd)
		return -EINVAL;

	buf = kmalloc(1024, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	sprintf(buf, "Name:\t%s\nPort:\t%lu\nGroup:\t%u\n",
				nd->srv.name,
				(unsigned long)nd->port,
				nd->srv.group);

	if (rim) {
		struct ipcon_msghdr *im = *rim;

		p = buf + strlen(buf);
		if (im) {
			int i;
			int len;
			char *data = (char *)IPCONMSG_DATA(im);
			char tmpc;

			sprintf(p, "Last msg in this group:\n");
			p = buf + strlen(buf);
			sprintf(p, "  Size: %lu\n  Dump:",
					(unsigned long)im->size);

			p = buf + strlen(buf);

			for (i = 0; i < im->size; i++) {
				if (i > 40)
					break;

				if (data[i] == '\0')
					tmpc = '0';
				else
					tmpc = data[i];

				len = sprintf(p, " 0x%x(\'%c\')",
						tmpc, tmpc);
				p += len;
			}

			*p = '\n';
			p++;
			*p = '\0';

		} else {
			sprintf(p, "No msg cached in this group.\n");
		}
	}

	ipcon_unlock();

	ret = simple_read_from_buffer(user_buffer,
				count,
				position,
				buf,
				strlen(buf) + 1);

	kfree(buf);

	return ret;
}

static const struct file_operations ipcon_debugfs_fops = {
	.read = srv_file_read,
};

int __init ipcon_debugfs_init(unsigned long int *groupbitflag)
{
	int ret = 0;

	diret = debugfs_create_dir("ipcon", NULL);

	grp_bit_flag = debugfs_create_u32("group_bit_flag",
				0644, diret, (u32 *)groupbitflag);

	service = debugfs_create_dir("service", diret);

	return ret;
}

int ipcon_debugfs_add_srv(struct ipcon_tree_node *nd,
		struct ipcon_msghdr **cached_msg)
{
	int ret = 0;

	if (!nd)
		return -EINVAL;

	nd->priv = (void *)debugfs_create_file(nd->srv.name,
						0644,
						service,
						cached_msg,
						&ipcon_debugfs_fops);
	return ret;
}

int ipcon_debugfs_remove_srv(struct ipcon_tree_node *nd)
{
	int ret = 0;

	if (!nd)
		return -EINVAL;

	debugfs_remove((struct dentry *)nd->priv);
	nd->priv = NULL;

	return ret;
}

void __exit ipcon_debugfs_exit(void)
{
	debugfs_remove_recursive(diret);
}
