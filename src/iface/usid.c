/*
 * This file is part of SID.
 *
 * Copyright (C) 2019 Red Hat, Inc. All rights reserved.
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

#include "iface/usid.h"

#include <string.h>

usid_cmd_t usid_cmd_name_to_type(const char *cmd_name)
{
	usid_cmd_t cmd;

	if (!cmd_name)
		return USID_CMD_UNDEFINED;

	for (cmd = _USID_CMD_START; cmd <= _USID_CMD_END; cmd++) {
		if (!strcmp(cmd_name, usid_cmd_names[cmd]))
			return cmd;
	}

	return USID_CMD_UNKNOWN;
}
