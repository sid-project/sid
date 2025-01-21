#
# SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include $(top_srcdir)/Makefile.common

udevdir = $(UDEV_DIR)

udev_PROGRAMS = usid

usid_SOURCES = usid.c

usid_LDADD = $(top_builddir)/src/base/libsidbase.la \
	     $(top_builddir)/src/iface/libsidiface.la \
	     $(top_builddir)/src/log/libsidlog.la

