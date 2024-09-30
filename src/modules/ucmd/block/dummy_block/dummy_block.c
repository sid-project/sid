/*
 * SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "resource/ucmd-mod.h"

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

static int _dummy_block_scan_a_init(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-a-init");
	return 0;
}
SID_UCMD_SCAN_A_INIT(_dummy_block_scan_a_init)

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

static int _dummy_block_scan_a_exit(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-a-exit");
	return 0;
}
SID_UCMD_SCAN_A_EXIT(_dummy_block_scan_a_exit)

static int _dummy_block_scan_remove_init(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-remove-init");
	return 0;
}
SID_UCMD_SCAN_REMOVE_INIT(_dummy_block_scan_remove_init)

static int _dummy_block_scan_remove(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-remove");
	return 0;
}
SID_UCMD_SCAN_REMOVE(_dummy_block_scan_remove)

static int _dummy_block_scan_remove_exit(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-remove-exit");
	return 0;
}
SID_UCMD_SCAN_REMOVE_EXIT(_dummy_block_scan_remove_exit)

static int _dummy_block_scan_b_init(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-b-init");
	return 0;
}
SID_UCMD_SCAN_B_INIT(_dummy_block_scan_b_init)

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

static int _dummy_block_scan_b_exit(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-b-exit");
	return 0;
}
SID_UCMD_SCAN_B_EXIT(_dummy_block_scan_b_exit)

static int _dummy_block_scan_error(sid_res_t *mod_res, struct sid_ucmd_ctx *ucmd_ctx)
{
	sid_res_log_debug(mod_res, "scan-error");
	return 0;
}
SID_UCMD_SCAN_ERROR(_dummy_block_scan_error)
