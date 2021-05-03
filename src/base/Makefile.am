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

pkglib_LTLIBRARIES = libsidbase.la

libsidbase_la_SOURCES = mem.c \
			bitmap.c \
			buffer-type.h \
			buffer-type-linear.c \
			buffer-type-vector.c \
			buffer.c \
			list.c \
			comms.c \
			util.c \
			hash.c \
			formatter.c \
			base64.c

basedir = $(pkgincludedir)/base

base_HEADERS = $(top_builddir)/src/include/base/common.h \
	       $(top_builddir)/src/include/base/mem.h \
	       $(top_builddir)/src/include/base/bitmap.h \
	       $(top_builddir)/src/include/base/buffer-common.h \
	       $(top_builddir)/src/include/base/buffer.h \
	       $(top_builddir)/src/include/base/list.h \
	       $(top_builddir)/src/include/base/comms.h \
	       $(top_builddir)/src/include/base/util.h

libsidbase_la_CFLAGS = $(UUID_CFLAGS)

libsidbase_la_LDFLAGS = -version-info 0:0:0

libsidbase_la_LIBADD = $(UUID_LIBS)

uninstall-hook:
	test -d ${DESTDIR}${basedir} && rmdir ${DESTDIR}${basedir}
