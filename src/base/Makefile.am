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

include $(top_srcdir)/Makefile.common

pkglib_LTLIBRARIES = libsidbase.la

libsidbase_la_SOURCES = buf-type-linear.c \
			buf-type-vector.c \
			buf.c \
			comms.c \
			conv.c \
			util.c

basedir = $(pkgincludedir)/base

base_HEADERS = $(top_srcdir)/src/include/base/buf-common.h \
	       $(top_srcdir)/src/include/base/buf-type.h \
	       $(top_srcdir)/src/include/base/buf.h \
	       $(top_srcdir)/src/include/base/comms.h \
	       $(top_srcdir)/src/include/base/conv.h \
	       $(top_srcdir)/src/include/base/util.h

libsidbase_la_LDFLAGS = -version-info 0:0:0

uninstall-hook:
	test -d ${DESTDIR}${basedir} && rmdir ${DESTDIR}${basedir}
