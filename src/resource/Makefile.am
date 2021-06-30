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
			    worker-control.c \
			    sid.c

resourcedir = $(pkgincludedir)/resource

resource_HEADERS = $(top_builddir)/src/include/resource/resource.h \
		   $(top_builddir)/src/include/resource/resource-type-regs.h \
		   $(top_builddir)/src/include/resource/module.h \
		   $(top_builddir)/src/include/resource/module-registry.h \
		   $(top_builddir)/src/include/resource/kv-store.h \
		   $(top_builddir)/src/include/resource/ucmd-module.h \
		   $(top_builddir)/src/include/resource/worker-control.h

libsidresource_la_CFLAGS = $(SYSTEMD_CFLAGS) \
			   $(UDEV_CFLAGS)

libsidresource_la_LDFLAGS = -version-info 0:0:0

libsidresource_la_LIBADD = $(top_builddir)/src/internal/libsidinternal.la \
			   $(top_builddir)/src/base/libsidbase.la \
			   $(top_builddir)/src/iface/libsidiface_servicelink.la \
			   $(top_builddir)/src/iface/libsidiface.la \
			   $(top_builddir)/src/log/libsidlog.la \
			   $(SYSTEMD_LIBS) \
			   $(UDEV_LIBS) \
			   -ldl

uninstall-hook:
	test -d ${DESTDIR}${resourcedir} && rmdir ${DESTDIR}${resourcedir}
