#
# SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include $(top_srcdir)/Makefile.common

dummy_typedir = $(pkglibdir)/modules/ucmd/type

dummy_type_LTLIBRARIES = dummy_type.la

dummy_type_la_SOURCES = dummy_type.c

dummy_type_la_LDFLAGS = -module -avoid-version

dummy_type_la_LIBADD = $(top_builddir)/src/resource/libsidresource.la
