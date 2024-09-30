#
# SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include $(top_srcdir)/Makefile.common

sbin_PROGRAMS = sidctl

sidctl_SOURCES = sidctl.c

sidctl_LDADD = $(top_builddir)/src/internal/libsidinternal.la \
	       $(top_builddir)/src/base/libsidbase.la \
	       $(top_builddir)/src/iface/libsidiface.la \
	       $(top_builddir)/src/log/libsidlog.la
