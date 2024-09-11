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

pkglib_LTLIBRARIES = libsidresource.la

libsidresource_la_SOURCES = res.c \
			    aggr.c \
			    ubr.c \
			    mod-reg.c \
			    kvs.c \
			    wrk-ctl.c \
			    sid.c

resourcedir = $(pkgincludedir)/resource

resource_HEADERS = $(top_srcdir)/src/include/resource/res.h \
		   $(top_srcdir)/src/include/resource/res-type-regs.h \
		   $(top_srcdir)/src/include/resource/mod.h \
		   $(top_srcdir)/src/include/resource/mod-reg.h \
		   $(top_srcdir)/src/include/resource/kvs.h \
		   $(top_srcdir)/src/include/resource/ucmd-mod.h \
		   $(top_srcdir)/src/include/resource/ubr.h \
		   $(top_srcdir)/src/include/resource/wrk-ctl.h

libsidresource_la_CFLAGS = $(SYSTEMD_CFLAGS) \
			   $(UDEV_CFLAGS)

libsidresource_la_LDFLAGS = -version-info 0:0:0

libsidresource_la_LIBADD = $(top_builddir)/src/internal/libsidinternal.la \
			   $(top_builddir)/src/base/libsidbase.la \
			   $(top_builddir)/src/iface/libsidiface_servicelink.la \
			   $(top_builddir)/src/iface/libsidiface.la \
			   $(SYSTEMD_LIBS) \
			   $(UDEV_LIBS) \
			   -ldl

uninstall-hook:
	test -d ${DESTDIR}${resourcedir} && rmdir ${DESTDIR}${resourcedir}
