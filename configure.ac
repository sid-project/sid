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

m4_define([VERSION_MAJOR], [0])
m4_define([VERSION_MINOR], [0])
m4_define([VERSION_RELEASE], [1])

AC_INIT([sid], [VERSION_MAJOR.VERSION_MINOR.VERSION_RELEASE], [prajnoha@redhat.com])
AC_CONFIG_AUX_DIR(autoconf)
AC_CONFIG_MACRO_DIRS([m4])
AC_GNU_SOURCE
CONFIGURE_LINE="$0 $@"
AM_INIT_AUTOMAKE([-Wall -Werror])
AM_SILENT_RULES([yes])
AM_PROG_AR
LT_INIT
AC_PROG_CC
AC_PROG_CXX
AC_DEFINE([SID_VERSION_MAJOR], [VERSION_MAJOR], [major version])
AC_DEFINE([SID_VERSION_MINOR], [VERSION_MINOR], [minor version])
AC_DEFINE([SID_VERSION_RELEASE], [VERSION_RELEASE], [release version])
AC_DEFINE_UNQUOTED(SID_CONFIGURE_LINE,"$CONFIGURE_LINE", [configure command line used])
AC_DEFINE_UNQUOTED(SID_COMPILED_BY, "$(whoami)", [user who ran configure])
AC_DEFINE_UNQUOTED(SID_COMPILATION_HOST, "$(hostname -f 2>/dev/null || hostname)", [host on which configure was executed])
AC_DEFINE_UNQUOTED(SID_COMPILER, "$($CC --version | head -n 1)", [compiler used to compile sources])
AC_CONFIG_FILES([Makefile log/Makefile misc/Makefile resource/Makefile daemon/Makefile
		 modules/Makefile modules/ubridge-cmd/Makefile modules/ubridge-cmd/type/Makefile
		 modules/ubridge-cmd/type/dummy_type/Makefile
		 modules/ubridge-cmd/type/device_mapper/Makefile])
AC_CONFIG_HEADERS([include/configure.h])
AC_CHECK_HEADERS([fcntl.h limits.h stddef.h stdlib.h syslog.h sys/socket.h])
AC_CHECK_HEADER_STDBOOL
AC_CHECK_FUNCS([clock_gettime dup2 memchr memset select socket strcasecmp strchr strerror strtoull])
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_TYPE_SSIZE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_FUNC_MALLOC
PKG_CHECK_MODULES(SYSTEMD, libsystemd >= 221) # event loop supported in libsystemd version >= 221
PKG_CHECK_MODULES(UDEV, libudev >= 174) # support for device tagging added in libudev version >= 174
AC_OUTPUT
