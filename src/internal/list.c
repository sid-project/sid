/*
 * SPDX-FileCopyrightText: (C) 2001-2004 Sistina Software, Inc.
 * SPDX-FileCopyrightText: (C) 2004-2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "internal/list.h"

void list_init(struct list *head)
{
	head->n = head->p = head;
}

void list_add(struct list *head, struct list *elem)
{
	elem->n    = head;
	elem->p    = head->p;
	head->p->n = elem;
	head->p    = elem;
}

void list_del(struct list *elem)
{
	elem->n->p = elem->p;
	elem->p->n = elem->n;
}

bool list_is_empty(const struct list *head)
{
	return head->n == head;
}

unsigned int list_get_size(const struct list *head)
{
	unsigned int       i = 0;
	const struct list *v;

	list_iterate (v, head)
		i++;

	return i;
}
