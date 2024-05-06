/*
 * This file is part of SID.
 *
 * Copyright (C) 2017-2020 Red Hat, Inc. All rights reserved.
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

#include "resource/ucmd-module.h"

SID_UCMD_MOD_PRIO(1)

static int _dummy_block_init(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	sid_res_log_debug(mod_res, "init");
	return 0;
}
SID_UCMD_MOD_INIT(_dummy_block_init)

static int _dummy_block_exit(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	sid_res_log_debug(mod_res, "exit");
	return 0;
}
SID_UCMD_MOD_EXIT(_dummy_block_exit)

static int _dummy_block_reset(sid_res_t *mod_res, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	sid_res_log_debug(mod_res, "reset");
	return 0;
}
SID_UCMD_MOD_RESET(_dummy_block_reset)

static int _dummy_block_scan_ident(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "ident");
	return 0;
}
SID_UCMD_SCAN_IDENT(_dummy_block_scan_ident)

static int _dummy_block_scan_pre(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-pre");
	return 0;
}
SID_UCMD_SCAN_PRE(_dummy_block_scan_pre)

static int _dummy_block_scan_current(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd)
{
	sid_res_log_debug(mod_res, "scan-current");
	return 0;
}
SID_UCMD_SCAN_CURRENT(_dummy_block_scan_current)

static int _dummy_block_scan_next(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-next");
	return 0;
}
SID_UCMD_SCAN_NEXT(_dummy_block_scan_next)

static int _dummy_block_scan_post_current(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-post-current");
	return 0;
}
SID_UCMD_SCAN_POST_CURRENT(_dummy_block_scan_post_current)

static int _dummy_block_scan_post_next(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-post-next");
	return 0;
}
SID_UCMD_SCAN_POST_NEXT(_dummy_block_scan_post_next)

static int _dummy_block_scan_remove(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-remove");
	return 0;
}
SID_UCMD_SCAN_REMOVE(_dummy_block_scan_remove)

static int _dummy_block_scan_action_current(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-action-current");
	return 0;
}
SID_UCMD_SCAN_ACTION_CURRENT(_dummy_block_scan_action_current)

static int _dummy_block_scan_action_next(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-action-next");
	return 0;
}
SID_UCMD_SCAN_ACTION_NEXT(_dummy_block_scan_action_next)

static int _dummy_block_error(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "error");
	return 0;
}
SID_UCMD_ERROR(_dummy_block_error)
