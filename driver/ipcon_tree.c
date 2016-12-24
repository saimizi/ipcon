/*
 * Copyright (C) 2016  Seimizu Joukan
 */

#include <linux/slab.h>
#include <linux/errno.h>
#include "ipcon_tree.h"

struct ipcon_tree_node *cp_alloc_node(struct ipcon_point *p, int port)
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
	newnd->port = port;

	return newnd;
}

void cp_free_node(struct ipcon_tree_node *nd)
{
	ipcon_info("Free point %s@%d.\n", nd->point.name, nd->port);
	kfree(nd);
}

struct ipcon_tree_node *cp_detach_node(struct ipcon_tree_node *nd)
{
	struct ipcon_tree_node *np = NULL;

	if (!nd || !cp_valid_node(nd))
		return NULL;

	if (nd->parent) {
		cp_insert(&nd->parent, nd->left);
		cp_insert(&nd->parent, nd->right);

		np = nd->parent;

		while (np->parent)
			np = np->parent;
	} else {
		if (nd->left) {
			nd->left->parent = NULL;
			cp_insert(&nd->left, nd->right);
			np = nd->left;
		} else if (nd->right) {
			nd->right->parent = NULL;
			np = nd->right;
		}
	}

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

int cp_insert(struct ipcon_tree_node **root, struct ipcon_tree_node *node)
{
	int ret = 0;
	struct ipcon_tree_node *it = NULL;

	if (!root || !cp_valid_node(node))
		return -EINVAL;

	if (*root == NULL) {
		*root = node;
		node->parent = NULL;
	} else {
		it = *root;

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

void cp_walk_tree(struct ipcon_tree_node *root,
		void (*process_node)(struct ipcon_tree_node *, void *),
		void *para)
{
	if (!root)
		return;

	if (root->left)
		cp_walk_tree(root->left, process_node, para);

	if (root->right)
		cp_walk_tree(root->right, process_node, para);

	process_node(root, para);
}

static void walk_free_node(struct ipcon_tree_node *nd, void *para)
{
	if (nd->parent) {
		if (nd->parent->left == nd)
			nd->parent->left = NULL;

		if (nd->parent->right == nd)
			nd->parent->right = NULL;
	}

	cp_free_node(nd);
}

void cp_free_tree(struct ipcon_tree_node *root)
{
	cp_walk_tree(root, walk_free_node, NULL);
}
