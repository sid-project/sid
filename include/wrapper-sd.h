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

#ifndef _SID_WRAPPER_SD_H
#define _SID_WRAPPER_SD_H

#include <systemd/sd-event.h>
#include <systemd/sd-id128.h>

#define sid_event_source sd_event_source
#define sid_io_handler sd_event_io_handler_t
#define sid_signal_handler sd_event_signal_handler_t
#define sid_child_handler sd_event_child_handler_t
#define sid_time_handler sd_event_time_handler_t
#define sid_generic_handler sd_event_handler_t

#define sid_uuid sd_id128_t

#endif
