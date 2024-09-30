#
# SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include $(top_srcdir)/Makefile.common

blkiddir = $(pkglibdir)/modules/ucmd/block

blkid-type-mapper.c: blkid-type-mapper.gperf
	$(AM_V_GEN) \
	if $(GPERF) $(GPERFFLAGS) < $< >$@.temp; then \
		mv $@.temp $@; \
	elif $(GPERF) --version >/dev/null 2>&1; then \
		$(RM) $@.temp; \
		exit 1; \
	else \
		$(RM) $@.temp; \
		touch $@; \
	fi

blkid_LTLIBRARIES = blkid.la

blkid_la_SOURCES = blkid-type.h \
		   blkid-type-mapper.c \
		   blkid.c

blkid_la_CFLAGS = $(BLKID_CFLAGS)

blkid_la_LDFLAGS = -module -avoid-version

blkid_la_LIBADD = $(top_builddir)/src/resource/libsidresource.la \
		  $(BLKID_LIBS)

EXTRA_DIST = blkid-type-mapper.gperf

mostlyclean-local:
	$(RM) blkid-type-mapper.c
