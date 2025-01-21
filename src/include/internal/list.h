/*
 * SPDX-FileCopyrightText: (C) 2001-2004 Sistina Software, Inc.
 * SPDX-FileCopyrightText: (C) 2004-2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#define list_iterate(v, head)        for (v = (head)->n; v != head; v = v->n)

#define list_iterate_back(v, head)   for (v = (head)->p; v != head; v = v->p)

#define list_struct_base(v, t, head) ((t *) ((char *) (v) - offsetof(t, head)))

#define list_item(v, t)              list_struct_base((v), t, list)

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
unsigned int list_get_size(const struct list *head);

#ifdef __cplusplus
}
#endif

#endif
