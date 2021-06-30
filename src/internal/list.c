/*
 * This file is part of SID.
 *
 * Copyright (C) 2017-2018 Red Hat, Inc. All rights reserved.
 *
 * SID is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * SID is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SID.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Code adopted from lvm2 source tree (https://sourceware.org/lvm2).
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

unsigned int list_size(const struct list *head)
{
	unsigned int       i = 0;
	const struct list *v;

	list_iterate (v, head)
		i++;

	return i;
}
