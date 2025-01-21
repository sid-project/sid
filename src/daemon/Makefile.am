#
# SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include $(top_srcdir)/Makefile.common

sbin_PROGRAMS = sid

sid_SOURCES = sid.c

sid_LDADD = $(top_builddir)/src/resource/libsidresource.la \
	    $(top_builddir)/src/internal/libsidinternal.la \
	    $(top_builddir)/src/base/libsidbase.la \
	    $(top_builddir)/src/log/libsidlog.la
