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

#include "log/log.h"
#include "resource/ucmd-module.h"

#define MID "dummy_block"

SID_UCMD_MOD_PRIO(1)

static int _dummy_block_init(struct module *module, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	log_debug(MID, "init");
	return 0;
}
SID_UCMD_MOD_INIT(_dummy_block_init)

static int _dummy_block_exit(struct module *module, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	log_debug(MID, "exit");
	return 0;
}
SID_UCMD_MOD_EXIT(_dummy_block_exit)

static int _dummy_block_reset(struct module *module, struct sid_ucmd_common_ctx *ucmd_common_ctx)
{
	log_debug(MID, "reset");
	return 0;
}
SID_UCMD_MOD_RESET(_dummy_block_reset)

static int _dummy_block_ident(struct module *module, struct sid_ucmd_ctx *ucmd_ctx)
{
	log_debug(MID, "ident");
	return 0;
}
SID_UCMD_IDENT(_dummy_block_ident)

static int _dummy_block_scan_pre(struct module *module, struct sid_ucmd_ctx *ucmd_ctx)
{
	log_debug(MID, "scan-pre");
	return 0;
}
SID_UCMD_SCAN_PRE(_dummy_block_scan_pre)

static int _dummy_block_scan_current(struct module *module, struct sid_ucmd_ctx *ucmd)
{
	log_debug(MID, "scan-current");
	return 0;
}
SID_UCMD_SCAN_CURRENT(_dummy_block_scan_current)

static int _dummy_block_scan_next(struct module *module, struct sid_ucmd_ctx *ucmd_ctx)
{
	log_debug(MID, "scan-next");
	return 0;
}
SID_UCMD_SCAN_NEXT(_dummy_block_scan_next)

static int _dummy_block_scan_post_current(struct module *module, struct sid_ucmd_ctx *ucmd_ctx)
{
	log_debug(MID, "scan-post-current");
	return 0;
}
SID_UCMD_SCAN_POST_CURRENT(_dummy_block_scan_post_current)

static int _dummy_block_scan_post_next(struct module *module, struct sid_ucmd_ctx *ucmd_ctx)
{
	log_debug(MID, "scan-post-next");
	return 0;
}
SID_UCMD_SCAN_POST_NEXT(_dummy_block_scan_post_next)

static int _dummy_block_trigger_action_current(struct module *module, struct sid_ucmd_ctx *ucmd_ctx)
{
	log_debug(MID, "trigger-action-current");
	return 0;
}
SID_UCMD_TRIGGER_ACTION_CURRENT(_dummy_block_trigger_action_current)

static int _dummy_block_trigger_action_next(struct module *module, struct sid_ucmd_ctx *ucmd_ctx)
{
	log_debug(MID, "trigger-action-next");
	return 0;
}
SID_UCMD_TRIGGER_ACTION_NEXT(_dummy_block_trigger_action_next)

static int _dummy_block_scan_remove(struct module *module, struct sid_ucmd_ctx *ucmd_ctx)
{
	log_debug(MID, "scan-remove");
	return 0;
}
SID_UCMD_SCAN_REMOVE(_dummy_block_scan_remove)

static int _dummy_block_error(struct module *module, struct sid_ucmd_ctx *ucmd_ctx)
{
	log_debug(MID, "error");
	return 0;
}
SID_UCMD_ERROR(_dummy_block_error)
