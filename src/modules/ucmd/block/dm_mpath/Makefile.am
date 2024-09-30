#
# SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include $(top_srcdir)/Makefile.common

dm_mpathdir = $(pkglibdir)/modules/ucmd/block

dm_mpath_LTLIBRARIES = dm_mpath.la

dm_mpath_la_SOURCES = dm_mpath.c

dm_mpath_la_LDFLAGS = -module -avoid-version

dm_mpath_la_LIBADD = $(top_builddir)/src/base/libsidbase.la \
		     $(top_builddir)/src/resource/libsidresource.la \
		     -lmpathvalid
