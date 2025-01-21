#
# SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

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
