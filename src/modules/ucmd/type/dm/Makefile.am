##############################################################################
# This file is part of SID.
#
# Copyright (C) 2020 Red Hat, Inc. All rights reserved.
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

if BUILD_MOD_UCMD_TYPE_DM__LVM
SUBDIRS = lvm
endif

dmdir = $(pkglibdir)/modules/ucmd/type

dm_LTLIBRARIES = dm.la

dm_la_SOURCES = dm.c dm.h

dm_la_LDFLAGS = -module -avoid-version

dm_la_LIBADD = $(top_builddir)/src/base/libsidbase.la \
	       $(top_builddir)/src/resource/libsidresource.la

install-data-local:
	${MKDIR_P} ${DESTDIR}${pkglibdir}/modules/ucmd/type/dm

uninstall-local:
	test -d ${DESTDIR}${pkglibdir}/modules/ucmd/type/dm && rmdir ${DESTDIR}${pkglibdir}/modules/ucmd/type/dm || true
