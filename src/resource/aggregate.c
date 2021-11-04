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

#include "resource/resource.h"

/*
 * This resource is only used to aggregate other resources.
 * There's no resource-specific implementation here.
 */

static int _init_aggregate(sid_resource_t *res, const void *kickstart_data, void **data)
{
	*data = (void *) kickstart_data;
	return 0;
}

const sid_resource_type_t sid_resource_type_aggregate = {
	.name        = "aggregate",
	.short_name  = "agg",
	.description = "Simple resource to aggregate other resources.",
	.init        = _init_aggregate,
};
