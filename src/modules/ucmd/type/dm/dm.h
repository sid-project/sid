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

#ifndef _SID_UCMD_MOD_TYPE_DM_H
#define _SID_UCMD_MOD_TYPE_DM_H

#ifdef __cplusplus
extern "C" {
#endif

#define SID_UCMD_DM_MOD_FN_NAME_SUBSYS_MATCH "sid_ucmd_dm_subsys_match"
#define SID_UCMD_MOD_DM_SUBSYS_MATCH(fn)     SID_UCMD_FN(dm_subsys_match, _SID_UCMD_FN_CHECK_TYPE(fn))

#ifdef __cplusplus
}
#endif

#endif
