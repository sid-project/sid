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

pkglib_LTLIBRARIES = libsidresource.la
libsidresource_la_SOURCES = resource.c \
			    aggregate.c \
			    ubridge.c \
			    module-registry.c \
			    kv-store.c \
			    worker-control.c
pkginclude_HEADERS = $(top_builddir)/include/wrapper-sd.h \
		     $(top_builddir)/include/types.h \
		     $(top_builddir)/include/resource.h \
		     $(top_builddir)/include/resource-regs.h \
		     $(top_builddir)/include/macros.h \
		     $(top_builddir)/include/module.h \
		     $(top_builddir)/include/module-registry.h \
		     $(top_builddir)/include/kv-store.h \
		     $(top_builddir)/include/worker-control.h
libsidresource_la_CFLAGS = $(SYSTEMD_CFLAGS) \
			   $(UDEV_CFLAGS)
libsidresource_la_LIBADD = $(top_builddir)/misc/libsidmisc.la \
			   $(SYSTEMD_LIBS) \
			   $(UDEV_LIBS) \
			   -ldl
