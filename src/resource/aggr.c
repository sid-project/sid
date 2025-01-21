/*
 * SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "resource/res.h"

/*
 * This resource is only used to aggregate other resources.
 * There's no resource-specific implementation here.
 */

static int _init_aggregate(sid_res_t *res, const void *kickstart_data, void **data)
{
	*data = (void *) kickstart_data;
	return 0;
}

const sid_res_type_t sid_res_type_aggr = {
	.name        = "aggregate",
	.short_name  = "agg",
	.description = "Simple resource to aggregate other resources.",
	.init        = _init_aggregate,
};
