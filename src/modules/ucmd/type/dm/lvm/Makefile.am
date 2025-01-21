#
# SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include $(top_srcdir)/Makefile.common

lvmdir = $(pkglibdir)/modules/ucmd/type/dm

lvm_LTLIBRARIES = lvm.la

lvm_la_SOURCES = lvm.c

lvm_la_LDFLAGS = -module -avoid-version

lvm_la_LIBADD = $(top_builddir)/src/base/libsidbase.la \
		$(top_builddir)/src/resource/libsidresource.la
