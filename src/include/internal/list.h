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

#ifndef _SID_LIST_H
#define _SID_LIST_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct list {
	struct list *n;
	struct list *p;
};

#define list_iterate(v, head) for (v = (head)->n; v != head; v = v->n)

#define list_iterate_back(v, head) for (v = (head)->p; v != head; v = v->p)

#define list_struct_base(v, t, head) ((t *) ((char *) (v) -offsetof(t, head)))

#define list_item(v, t) list_struct_base((v), t, list)

#define list_iterate_items_gen(v, head, field)                                                                                     \
	for (v = list_struct_base((head)->n, __typeof__(*v), field); &v->field != (head);                                          \
	     v = list_struct_base(v->field.n, __typeof__(*v), field))

#define list_iterate_items(v, head) list_iterate_items_gen (v, (head), list)

#define list_iterate_items_gen_back(v, head, field)                                                                                \
	for (v = list_struct_base((head)->p, __typeof__(*v), field); &v->field != (head);                                          \
	     v = list_struct_base(v->field.p, __typeof__(*v), field))

#define list_iterate_items_back(v, head) list_iterate_items_gen_back (v, (head), list)

#define list_iterate_items_gen_safe(v, t, head, field)                                                                             \
	for (v = list_struct_base((head)->n, __typeof__(*v), field), t = list_struct_base(v->field.n, __typeof__(*v), field);      \
	     &v->field != (head);                                                                                                  \
	     v = t, t = list_struct_base(v->field.n, __typeof__(*v), field))

#define list_iterate_items_safe(v, t, head) list_iterate_items_gen_safe (v, t, (head), list)

#define list_iterate_items_gen_safe_back(v, t, head, field)                                                                        \
	for (v = list_struct_base((head)->p, __typeof__(*v), field), t = list_struct_base(v->field.p, __typeof__(*v), field);      \
	     &v->field != (head);                                                                                                  \
	     v = t, t = list_struct_base(v->field.p, __typeof__(*v), field))

#define list_iterate_items_safe_back(v, t, head) list_iterate_items_gen_safe_back (v, t, (head), list)

void         list_init(struct list *head);
void         list_add(struct list *head, struct list *elem);
void         list_del(struct list *elem);
bool         list_is_empty(const struct list *head);
unsigned int list_size(const struct list *head);

#ifdef __cplusplus
}
#endif

#endif
