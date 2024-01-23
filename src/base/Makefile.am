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

libsidbase_la_SOURCES = buffer-type-linear.c \
			buffer-type-vector.c \
			buffer.c \
			comms.c \
			util.c \
			binary.c

basedir = $(pkgincludedir)/base

base_HEADERS = $(top_builddir)/src/include/base/buffer-common.h \
	       $(top_builddir)/src/include/base/buffer-type.h \
	       $(top_builddir)/src/include/base/buffer.h \
	       $(top_builddir)/src/include/base/comms.h \
	       $(top_builddir)/src/include/base/util.h \
	       $(top_builddir)/src/include/base/binary.h

libsidbase_la_LDFLAGS = -version-info 0:0:0

uninstall-hook:
	test -d ${DESTDIR}${basedir} && rmdir ${DESTDIR}${basedir}
