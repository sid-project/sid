#
# SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include $(top_srcdir)/Makefile.common

pkglib_LTLIBRARIES = libsidinternal.la

libsidinternal_la_SOURCES = mem.c \
			    bmp.c \
			    list.c \
			    util.c \
			    hash.c \
			    fmt.c \
			    bptree.c

internaldir = $(pkgincludedir)/internal

internal_HEADERS = $(top_srcdir)/src/include/internal/common.h \
		   $(top_srcdir)/src/include/internal/comp-attrs.h \
		   $(top_srcdir)/src/include/internal/mem.h \
		   $(top_srcdir)/src/include/internal/bmp.h \
		   $(top_srcdir)/src/include/internal/list.h \
		   $(top_srcdir)/src/include/internal/util.h \
		   $(top_srcdir)/src/include/internal/fmt.h \
		   $(top_srcdir)/src/include/internal/hash.h \
		   $(top_srcdir)/src/include/internal/bptree.h

libsidinternal_la_CFLAGS = $(UUID_CFLAGS)

libsidinternal_la_LDFLAGS = -version-info 0:0:0

libsidinternal_la_LIBADD = $(UUID_LIBS) $(top_builddir)/src/base/libsidbase.la

uninstall-hook:
	test -d ${DESTDIR}${internaldir} && rmdir ${DESTDIR}${internaldir}
