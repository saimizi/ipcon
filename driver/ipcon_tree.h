/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#ifndef __IPCON_TREE_H__
#define __IPCON_TREE_H__

#include <linux/string.h>
#include "ipcon.h"
#include "ipcon_dbg.h"

struct ipcon_tree_node {
	struct ipcon_point point;
	int port;
	struct ipcon_tree_node *parent;
	struct ipcon_tree_node *left;
	struct ipcon_tree_node *right;
};

static inline int cp_valid_node(struct ipcon_tree_node *node)
{
	if (!node)
		return 0;

	if (node->port <= 0)
		return 0;

	if (strlen(node->point.name) == 0)
		return 0;

	return 1;
}

int cp_comp(struct ipcon_tree_node *n1, struct ipcon_tree_node *n2);
struct ipcon_tree_node *cp_alloc_node(struct ipcon_point *p, int port);
void cp_free_node(struct ipcon_tree_node *nd);
struct ipcon_tree_node *cp_detach_node(struct ipcon_tree_node *nd);
struct ipcon_tree_node *cp_lookup(struct ipcon_tree_node *root, char *name);
void cp_init_node(struct ipcon_tree_node *node);
int cp_insert(struct ipcon_tree_node **root, struct ipcon_tree_node *node);
int cp_walk_tree(struct ipcon_tree_node *root,
		int (*process_node)(struct ipcon_tree_node *, void *),
		void *para, int order, int stop_on_error);
void cp_free_tree(struct ipcon_tree_node *root);
void cp_print_tree(struct ipcon_tree_node *root);

#endif
