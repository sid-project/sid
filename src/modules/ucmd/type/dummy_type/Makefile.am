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

dummy_typedir = $(pkglibdir)/modules/ucmd/type

dummy_type_LTLIBRARIES = dummy_type.la

dummy_type_la_SOURCES = dummy_type.c

dummy_type_la_LDFLAGS = -module -avoid-version

dummy_type_la_LIBADD = $(top_builddir)/src/log/libsidlog.la
