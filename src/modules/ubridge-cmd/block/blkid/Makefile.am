##############################################################################
# This file is part of SID.
#
# Copyright (C) 2017-2018 Red Hat, Inc. All rights reserved.
#
# SID is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# SID is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with SID.  If not, see <http://www.gnu.org/licenses/>.
##############################################################################

blkiddir = $(pkglibdir)/modules/ubridge-cmd/block

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
blkid_la_LDFLAGS = -module -avoid-version
blkid_la_LIBADD = $(top_builddir)/src/log/libsidlog.la \
		  $(BLKID_LIBS)

mostlyclean-local:
	$(RM) blkid-type-mapper.c
