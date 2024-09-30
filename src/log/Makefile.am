#
# SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include $(top_srcdir)/Makefile.common

pkglib_LTLIBRARIES = libsidlog.la

libsidlog_la_SOURCES = log-target-standard.c \
		       log-target-syslog.c \
		       log-target-journal.c \
		       log.c

logdir = $(pkgincludedir)/log

log_HEADERS = $(top_srcdir)/src/include/log/log.h

libsidlog_la_LIBADD = $(SYSTEMD_LIBS)

libsidlog_la_LDFLAGS = -version-info 0:0:0

uninstall-hook:
	test -d ${DESTDIR}${logdir} && rmdir ${DESTDIR}${logdir}
