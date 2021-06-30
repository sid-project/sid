##############################################################################
# This file is part of SID.
#
# Copyright (C) 2019 Red Hat, Inc. All rights reserved.
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

pkglib_LTLIBRARIES = libsidiface_servicelink.la libsidiface.la

ifacedir = $(pkgincludedir)/iface

libsidiface_servicelink_la_SOURCES = service-link.c

iface_servicelinkdir = ${ifacedir}

iface_servicelink_HEADERS = $(top_builddir)/src/include/iface/service-link.h

libsidiface_servicelink_la_CFLAGS = $(SYSTEMD_CFLAGS)

libsidiface_servicelink_la_LDFLAGS = -version-info 0:0:0

libsidiface_servicelink_la_LIBADD = $(top_builddir)/src/internal/libsidinternal.la \
				    $(top_builddir)/src/base/libsidbase.la \
				    $(SYSTEMD_LIBS)

libsidiface_la_SOURCES = iface.c

libsidiface_la_LIBADD = $(top_builddir)/src/base/libsidbase.la

iface_HEADERS = $(top_builddir)/src/include/iface/iface.h

libsidiface_la_LDFLAGS = -version-info 0:0:0

uninstall-hook:
	test -d ${DESTDIR}${ifacedir} && rmdir ${DESTDIR}${ifacedir}
