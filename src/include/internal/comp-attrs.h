/*
 * This file is part of SID.
 *
 * Copyright (C) 2023 Red Hat, Inc. All rights reserved.
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
