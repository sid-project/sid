#
# SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include $(top_srcdir)/Makefile.common

pkglib_LTLIBRARIES = libsidiface_servicelink.la libsidiface.la

ifacedir = $(pkgincludedir)/iface

libsidiface_servicelink_la_SOURCES = srv-lnk.c

iface_servicelinkdir = ${ifacedir}

iface_servicelink_HEADERS = $(top_srcdir)/src/include/iface/srv-lnk.h

libsidiface_servicelink_la_CFLAGS = $(SYSTEMD_CFLAGS)

libsidiface_servicelink_la_LDFLAGS = -version-info 0:0:0

libsidiface_servicelink_la_LIBADD = $(top_builddir)/src/internal/libsidinternal.la \
				    $(top_builddir)/src/base/libsidbase.la \
				    $(top_builddir)/src/log/libsidlog.la \
				    $(SYSTEMD_LIBS)

libsidiface_la_SOURCES = ifc.c

libsidiface_la_LIBADD = $(top_builddir)/src/base/libsidbase.la

iface_HEADERS = $(top_srcdir)/src/include/iface/ifc.h \
		$(top_srcdir)/src/include/iface/ifc-internal.h

libsidiface_la_LDFLAGS = -version-info 0:0:0

uninstall-hook:
	test -d ${DESTDIR}${ifacedir} && rmdir ${DESTDIR}${ifacedir}
