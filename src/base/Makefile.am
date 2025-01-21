#
# SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include $(top_srcdir)/Makefile.common

pkglib_LTLIBRARIES = libsidbase.la

libsidbase_la_SOURCES = buf-type-linear.c \
			buf-type-vector.c \
			buf.c \
			comms.c \
			conv-base64.c \
			util.c

basedir = $(pkgincludedir)/base

base_HEADERS = $(top_srcdir)/src/include/base/buf-common.h \
	       $(top_srcdir)/src/include/base/buf-type.h \
	       $(top_srcdir)/src/include/base/buf.h \
	       $(top_srcdir)/src/include/base/comms.h \
	       $(top_srcdir)/src/include/base/conv-base64.h \
	       $(top_srcdir)/src/include/base/conv.h \
	       $(top_srcdir)/src/include/base/util.h

libsidbase_la_LDFLAGS = -version-info 0:0:0

uninstall-hook:
	test -d ${DESTDIR}${basedir} && rmdir ${DESTDIR}${basedir}
