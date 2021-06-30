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

pkglib_LTLIBRARIES = libsidinternal.la

libsidinternal_la_SOURCES = mem.c \
			    bitmap.c \
			    list.c \
			    util.c \
			    hash.c \
			    formatter.c

internaldir = $(pkgincludedir)/internal

internal_HEADERS = $(top_builddir)/src/include/internal/common.h \
		   $(top_builddir)/src/include/internal/mem.h \
		   $(top_builddir)/src/include/internal/bitmap.h \
		   $(top_builddir)/src/include/internal/list.h \
		   $(top_builddir)/src/include/internal/util.h \
		   $(top_builddir)/src/include/internal/formatter.h \
		   $(top_builddir)/src/include/internal/hash.h

libsidinternal_la_CFLAGS = $(UUID_CFLAGS)

libsidinternal_la_LDFLAGS = -version-info 0:0:0

libsidinternal_la_LIBADD = $(UUID_LIBS) $(top_builddir)/src/base/libsidbase.la

uninstall-hook:
	test -d ${DESTDIR}${internaldir} && rmdir ${DESTDIR}${internaldir}
