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

pkglib_LTLIBRARIES = libsidiface.la
libsidiface_la_SOURCES = service-link-iface.c \
			 usid-iface.c
pkginclude_HEADERS = $(top_builddir)/src/include/service-link-iface.h \
		     $(top_builddir)/src/include/usid-iface.h
libsidiface_la_LIBADD = $(top_builddir)/src/misc/libsidmisc.la \
			$(SYSTEMD_LIBS)
