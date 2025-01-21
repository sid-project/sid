#
# SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include $(top_srcdir)/Makefile.common

dummy_blockdir = $(pkglibdir)/modules/ucmd/block

dummy_block_LTLIBRARIES = dummy_block.la

dummy_block_la_SOURCES = dummy_block.c

dummy_block_la_LDFLAGS = -module -avoid-version

dummy_block_la_LIBADD = $(top_builddir)/src/resource/libsidresource.la
