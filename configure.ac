##############################################################################
# This file is part of SID.
#
# Copyright (C) 2017-2020 Red Hat, Inc. All rights reserved.
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
m4_define([VERSION_RELEASE], [5])

AC_INIT([sid], [VERSION_MAJOR.VERSION_MINOR.VERSION_RELEASE], [prajnoha@redhat.com])
AC_CONFIG_AUX_DIR(autoconf)
AC_CONFIG_MACRO_DIRS([m4])
AC_USE_SYSTEM_EXTENSIONS([_GNU_SOURCE])
AC_REQUIRE_AUX_FILE([tap-driver.sh])
CONFIGURE_LINE="$(echo "$0 $ac_configure_args")"
AM_INIT_AUTOMAKE([foreign -Wall -Werror -Wno-portability])
AM_SILENT_RULES([yes])
AM_MISSING_PROG([GPERF], [gperf])
AM_PROG_AR
LT_INIT
AC_PROG_CC
AC_PROG_CXX
AC_PROG_MKDIR_P
AC_DEFINE([SID_VERSION_MAJOR], [VERSION_MAJOR], [major version])
AC_DEFINE([SID_VERSION_MINOR], [VERSION_MINOR], [minor version])
AC_DEFINE([SID_VERSION_RELEASE], [VERSION_RELEASE], [release version])
AC_DEFINE_UNQUOTED(SID_CONFIGURE_LINE,"$CONFIGURE_LINE", [configure command line used])
AC_DEFINE_UNQUOTED(SID_COMPILED_BY, "$(whoami)", [user who ran configure])
AC_DEFINE_UNQUOTED(SID_COMPILATION_HOST, "$(hostname -f 2>/dev/null || hostname)", [host on which configure was executed])
AC_DEFINE_UNQUOTED(SID_COMPILER, "$($CC --version | head -n 1)", [compiler used to compile sources])

AS_AC_EXPAND(LIBDIR, $libdir)
AC_DEFINE_UNQUOTED(LIBDIR, "$LIBDIR", [library directory])

AC_CONFIG_FILES([Makefile
		 src/Makefile
		 src/log/Makefile
		 src/iface/Makefile
		 src/internal/Makefile
		 src/base/Makefile
		 src/resource/Makefile
		 src/daemon/Makefile
		 src/modules/Makefile
		 src/modules/ucmd/Makefile
		 src/modules/ucmd/type/Makefile
		 src/modules/ucmd/block/Makefile
		 src/modules/ucmd/type/dummy_type/Makefile
		 src/modules/ucmd/type/dm/Makefile
		 src/modules/ucmd/block/dummy_block/Makefile
		 src/modules/ucmd/block/blkid/Makefile
		 src/modules/ucmd/block/dm_mpath/Makefile
		 src/tools/Makefile
		 src/tools/usid/Makefile
		 src/tools/sidctl/Makefile
		 udev/Makefile
		 systemd/Makefile
		 man/Makefile
		 tests/Makefile])

AC_CONFIG_HEADERS([src/include/config.h])
AC_CHECK_HEADERS([fcntl.h limits.h stddef.h stdlib.h syslog.h sys/socket.h])
AC_CHECK_HEADER_STDBOOL
AC_CHECK_FUNCS([clock_gettime dup2 memchr memset mkdir munmap select socket strcasecmp strchr strdup strerror strspn strstr strtoul strtoull])
AC_C_INLINE
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_HEADER_MAJOR
AC_TYPE_SSIZE_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_INT64_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC

PKG_CHECK_MODULES(SYSTEMD, libsystemd >= 221) # event loop supported in libsystemd version >= 221

PKG_CHECK_MODULES(UDEV, libudev >= 174) # support for device tagging added in libudev version >= 174

PKG_CHECK_MODULES(BLKID, blkid)

PKG_CHECK_MODULES(UUID, uuid)

AC_MSG_CHECKING(for systemd system unit directory)
PKG_CHECK_VAR(SYSTEMD_SYSTEM_UNIT_DIR, systemd, systemdsystemunitdir)
AC_MSG_RESULT($SYSTEMD_SYSTEM_UNIT_DIR)

AC_MSG_CHECKING(for sysconfig directory)
AC_ARG_WITH(sysconfigdir,
	    AS_HELP_STRING([--with-sysconfigdir=DIR],
			   [install sysconfig files to DIR [SYSCONFDIR/sysconfig]]),
			   [sysconfdir=${withval}],
			   [sysconfigdir="${sysconfdir}/sysconfig"])
AC_MSG_RESULT([$sysconfigdir])

AC_MSG_CHECKING(for systemd system unit installation directory)
AC_ARG_WITH(systemdsystemunitdir,
	    AS_HELP_STRING([--with-systemdsystemunitdir=DIR],
			   [install systemd system units to DIR [SYSTEMD_SYSTEM_UNIT_DIR]]),
			   [systemdsystemunitdir=$withval],
			   [systemdsystemunitdir="$SYSTEMD_SYSTEM_UNIT_DIR"])
AC_MSG_RESULT([$systemdsystemunitdir])

AC_MSG_CHECKING(for udev directory)
PKG_CHECK_VAR(UDEV_DIR, udev, udevdir)
AC_MSG_RESULT($UDEV_DIR)

AC_MSG_CHECKING(for udev rule installation directory)
AC_ARG_WITH(udevrulesdir,
	    AS_HELP_STRING([--with-udevrulesdir=DIR],
			   [install udev rules to DIR [UDEV_DIR/rules.d]]),
			   [udevrulesdir=$withval],
			   [udevrulesdir="${UDEV_DIR}/rules.d"])
AC_MSG_RESULT([$udevrulesdir])

AC_MSG_CHECKING(whether to build dm_mpath module)
AC_ARG_ENABLE(mod-dm_mpath,
	      AS_HELP_STRING([--enable-mod-dm_mpath], [enable device-mapper multipath module]),
	      BUILD_MOD_UCMD_BLOCK_DM_MPATH=$enableval,
	      BUILD_MOD_UCMD_BLOCK_DM_MPATH=yes)
AC_MSG_RESULT($BUILD_MOD_UCMD_BLOCK_DM_MPATH)
if test x$BUILD_MOD_UCMD_BLOCK_DM_MPATH = xyes; then
	AC_CHECK_HEADER([mpath_valid.h], , [AC_MSG_ERROR(--enable-mod-dm_mpath requires mpath_valid.h)])
	AC_DEFINE([MOD_UCMD_BLOCK_DM_MPATH], 1, [Define to 1 to enable device-mapper multipath module.])
fi
AM_CONDITIONAL([BUILD_MOD_UCMD_BLOCK_DM_MPATH], [test x$BUILD_MOD_UCMD_BLOCK_DM_MPATH = xyes])

AC_SUBST([sysconfigdir])
AC_SUBST([systemdsystemunitdir])
AC_SUBST([udevrulesdir])

AC_OUTPUT
AM_CHECK_CMOCKA
