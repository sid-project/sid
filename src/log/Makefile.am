##############################################################################
# This file is part of SID.
#
# Copyright (C) 2017-2018 Red Hat, Inc. All rights reserved.
#
# SID is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# SID is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with SID.  If not, see <http://www.gnu.org/licenses/>.
##############################################################################

pkglib_LTLIBRARIES = libsidlog.la

libsidlog_la_SOURCES = log-target-standard.c \
		       log-target-syslog.c \
		       log-target-journal.c \
		       log.c

logdir = $(pkgincludedir)/log

log_HEADERS = $(top_builddir)/src/include/log/log.h

libsidlog_la_LIBADD = $(SYSTEMD_LIBS)

libsidlog_la_LDFLAGS = -version-info 0:0:0

uninstall-hook:
	test -d ${logdir} && rmdir ${logdir}
