/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <linux/slab.h>
#include <linux/errno.h>
#include "ipcon_tree.h"

struct ipcon_tree_node *cp_alloc_node(struct ipcon_point *p)
{
	struct ipcon_tree_node *newnd;

	if (!p)
		return NULL;

	/* TODO:
	 * Check whether cp_alloc_node() maybe called from
	 * an atomic context.
	 */
	newnd = kmalloc(sizeof(struct ipcon_tree_node), GFP_KERNEL);
	if (!newnd)
		return NULL;

	memcpy(&newnd->point, p, sizeof(*p));
	newnd->left = newnd->right = newnd->parent = NULL;

	return newnd;
}

void cp_free_node(struct ipcon_tree_node *nd)
{
	kfree(nd);
}

struct ipcon_tree_node *cp_detach_node(struct ipcon_tree_node *nd)
{
	struct ipcon_tree_node *np = NULL;

	if (!nd || !cp_valid_node(nd))
		return NULL;

	np = nd->parent;
	cp_insert(np, nd->left);
	cp_insert(np, nd->right);

	while (np->parent)
		np = np->parent;

	nd->parent = nd->left = nd->right = NULL;

	return np;

}

struct ipcon_tree_node *cp_lookup(struct ipcon_tree_node *root, char *name)
{
	struct ipcon_tree_node *result = NULL;

	if (!name || !root || !cp_valid_node(root))
		return NULL;

	result = root;

	while (result) {
		int ret = strcmp(result->point.name, name);

		if (ret == 0)
			break;
		else if (ret == 1)
			result = result->left;
		else if (ret == -1)
			result = result->right;
		else
			result = NULL;
	}

	return result;
}

void cp_init_node(struct ipcon_tree_node *node)
{
	if (node)
		memset(node, 0, sizeof(node));
}

/*
 * Compare two nodes by using name.
 *
 * Return value
 * - n1 < n2: -1
 * - n1 = n2: 0
 * - n1 > n2: 1
 * - error:
 *	return a negative value beside -1.
 */
int cp_comp(struct ipcon_tree_node *n1, struct ipcon_tree_node *n2)
{

	if (!cp_valid_node(n1) || !cp_valid_node(n2))
		return -EINVAL;

	return strcmp(n1->point.name, n2->point.name);
}

int cp_insert(struct ipcon_tree_node *root, struct ipcon_tree_node *node)
{
	int ret = 0;
	struct ipcon_tree_node *it = NULL;

	if (!cp_valid_node(node))
		return -EINVAL;

	if (!root) {
		root = node;
		node->parent = NULL;
	} else {
		it = root;

		while (it) {
			ret = cp_comp(it, node);
			if (ret == -1) {
				if (!it->right) {
					it->right = node;
					node->parent = it;
					break;
				}

				it = it->right;

			} else if (ret == 1) {
				if (!it->left) {
					it->left = node;
					node->parent = it;
					break;
				}

				it = it->left;

			} else {
				if (ret == 0)
					ret = -EEXIST;
				break;
			}
		}
	}

	return ret;
}
