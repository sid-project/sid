/*
 * SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _SID_COMP_ATTRS_H
#define _SID_COMP_ATTRS_H

#ifdef __cplusplus
extern "C" {
#endif

/* variable attributes */
#define __packed              __attribute__((packed))
#define __unused              __attribute__((unused))
#define __aligned             __attribute__((aligned))
#define __aligned_to(x)       __attribute__((aligned(x)))
#define __malloc              __attribute__((malloc))

/* function attributes */
#define __format_printf(x, y) __attribute__((format(printf, x, y)))
#define __constructor         __attribute__((constructor))

#ifdef __cplusplus
}
#endif

#endif
