#
# SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

m4_define([VERSION_MAJOR], [0])
m4_define([VERSION_MINOR], [0])
m4_define([VERSION_RELEASE], [6])

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
AC_PROG_CPP
AC_PROG_CXX
AC_PROG_MKDIR_P
AC_TYPE_OFF_T
AC_DEFINE([SID_VERSION_MAJOR], [VERSION_MAJOR], [major version])
AC_DEFINE([SID_VERSION_MINOR], [VERSION_MINOR], [minor version])
AC_DEFINE([SID_VERSION_RELEASE], [VERSION_RELEASE], [release version])
AC_DEFINE_UNQUOTED(SID_CONFIGURE_LINE,"$CONFIGURE_LINE", [configure command line used])
AC_DEFINE_UNQUOTED(SID_COMPILED_BY, "$(whoami)", [user who ran configure])
AC_DEFINE_UNQUOTED(SID_COMPILATION_HOST, "$(hostname -f 2>/dev/null || hostname)", [host on which configure was executed])
AC_DEFINE_UNQUOTED(SID_COMPILER, "$($CC --version | head -n 1)", [compiler used to compile sources])

AS_AC_EXPAND(LIBDIR, $libdir)
AC_DEFINE_UNQUOTED(LIBDIR, "$LIBDIR", [library directory])
AS_AC_EXPAND(SBINDIR, $sbindir)
AC_DEFINE_UNQUOTED(SBINDIR, "$SBINDIR", [system admin executables directory])

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
		 src/modules/ucmd/type/dm/lvm/Makefile
		 src/modules/ucmd/block/dummy_block/Makefile
		 src/modules/ucmd/block/blkid/Makefile
		 src/modules/ucmd/block/dm_mpath/Makefile
		 src/tools/Makefile
		 src/tools/usid/Makefile
		 src/tools/sidctl/Makefile
		 udev/Makefile
		 systemd/Makefile
		 man/Makefile
		 man/sid.8
		 tests/Makefile])

AC_CONFIG_HEADERS([src/include/config.h])
AC_CHECK_HEADERS([fcntl.h inttypes.h limits.h stddef.h stdint.h stdlib.h syslog.h sys/ioctl.h sys/socket.h unistd.h])
AC_CHECK_HEADER_STDBOOL
AC_CHECK_FUNCS([atexit clock_gettime dup2 ftruncate memchr memset mkdir munmap select socket stpcpy strcasecmp strchr strcspn strdup strerror strncasecmp strndup strpbrk strrchr strspn strstr strtol strtoul strtoull])
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

PKG_CHECK_MODULES(UUID, uuid)

AC_MSG_CHECKING(whether to build with valgrind support)
AC_ARG_ENABLE(valgrind,
	      AS_HELP_STRING([--enable-valgrind], [enable valgrind support]),
	      BUILD_VALGRIND_SUPPORT=$enableval,
	      BUILD_VALGRIND_SUPPORT=no)
AC_MSG_RESULT($BUILD_VALGRIND_SUPPORT)
if test x$BUILD_VALGRIND_SUPPORT = xyes; then
	PKG_CHECK_MODULES(VALGRIND, valgrind)
	AC_DEFINE([VALGRIND_SUPPORT], 1, [Define to 1 to enable valgrind support])
fi
AM_CONDITIONAL([BUILD_VALGRIND_SUPPORT], [test x$BUILD_VALGRIND_SUPPORT = xyes])

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

AC_MSG_CHECKING(whether to build blkid block module)
AC_ARG_ENABLE(mod-block-blkid,
	      AS_HELP_STRING([--enable-mod-block-blkid], [enable blkid block module]),
	      BUILD_MOD_UCMD_BLOCK_BLKID=$enableval,
	      BUILD_MOD_UCMD_BLOCK_BLKID=yes)
AC_MSG_RESULT($BUILD_MOD_UCMD_BLOCK_BLKID)
if test x$BUILD_MOD_UCMD_BLOCK_BLKID = xyes; then
	PKG_CHECK_MODULES(BLKID, blkid)
	AC_DEFINE([MOD_UCMD_BLOCK_BLKID], 1, [Define to 1 to enable blkid block module.])
fi
AM_CONDITIONAL([BUILD_MOD_UCMD_BLOCK_BLKID], [test x$BUILD_MOD_UCMD_BLOCK_BLKID = xyes])

AC_MSG_CHECKING(whether to build dm_mpath block module)
AC_ARG_ENABLE(mod-block-dm_mpath,
	      AS_HELP_STRING([--enable-mod-block-dm_mpath], [enable device-mapper multipath block module]),
	      BUILD_MOD_UCMD_BLOCK_DM_MPATH=$enableval,
	      BUILD_MOD_UCMD_BLOCK_DM_MPATH=yes)
AC_MSG_RESULT($BUILD_MOD_UCMD_BLOCK_DM_MPATH)
if test x$BUILD_MOD_UCMD_BLOCK_DM_MPATH = xyes; then
	AC_CHECK_HEADER([mpath_valid.h], , [AC_MSG_ERROR(--enable-mod-block-dm_mpath requires mpath_valid.h)])
	AC_DEFINE([MOD_UCMD_BLOCK_DM_MPATH], 1, [Define to 1 to enable device-mapper multipath block module.])
fi
AM_CONDITIONAL([BUILD_MOD_UCMD_BLOCK_DM_MPATH], [test x$BUILD_MOD_UCMD_BLOCK_DM_MPATH = xyes])

AC_MSG_CHECKING(whether to build dummy block module)
AC_ARG_ENABLE(mod-block-dummy,
	      AS_HELP_STRING([--enable-mod-block-dummy], [enable dummy block module]),
	      BUILD_MOD_UCMD_BLOCK_DUMMY=$enableval,
	      BUILD_MOD_UCMD_BLOCK_DUMMY=no)
AC_MSG_RESULT($BUILD_MOD_UCMD_BLOCK_DUMMY)
if test x$BUILD_MOD_UCMD_BLOCK_DUMMY = xyes; then
	AC_DEFINE([MOD_UCMD_BLOCK_DUMMY], 1, [Define to 1 to enable dummy block module.])
fi
AM_CONDITIONAL([BUILD_MOD_UCMD_BLOCK_DUMMY], [test x$BUILD_MOD_UCMD_BLOCK_DUMMY = xyes])

AC_MSG_CHECKING(whether to build dm type module)
AC_ARG_ENABLE(mod-type-dm,
	      AS_HELP_STRING([--enable-mod-type-dm], [enable device-mapper type module]),
	      BUILD_MOD_UCMD_TYPE_DM=$enableval,
	      BUILD_MOD_UCMD_TYPE_DM=yes)
AC_MSG_RESULT($BUILD_MOD_UCMD_TYPE_DM)
if test x$BUILD_MOD_UCMD_TYPE_DM = xyes; then
	AC_DEFINE([MOD_UCMD_TYPE_DM], 1, [Define to 1 to enable device-mapper type module.])
fi
AM_CONDITIONAL([BUILD_MOD_UCMD_TYPE_DM], [test x$BUILD_MOD_UCMD_TYPE_DM = xyes])

AC_MSG_CHECKING(whether to build dm/lvm type module)
AC_ARG_ENABLE(mod-type-dm-lvm,
	      AS_HELP_STRING([--enable-mod-type-dm-lvm], [enable device-mapper/LVM type module]),
	      BUILD_MOD_UCMD_TYPE_DM__LVM=$enableval,
	      BUILD_MOD_UCMD_TYPE_DM__LVM=yes)
AC_MSG_RESULT($BUILD_MOD_UCMD_TYPE_DM__LVM)
if test x$BUILD_MOD_UCMD_TYPE_DM__LVM = xyes; then
	AS_IF([test x$BUILD_MOD_UCMD_TYPE_DM != xyes], AC_MSG_ERROR([--enable-mod-type-dm-lvm requires --enable-mod-type-dm]))
	AC_DEFINE([MOD_UCMD_TYPE_DM__LVM], 1, [Define to 1 to enable device-mapper/LVM type module.])
fi
AM_CONDITIONAL([BUILD_MOD_UCMD_TYPE_DM__LVM], [test x$BUILD_MOD_UCMD_TYPE_DM__LVM = xyes])

AC_MSG_CHECKING(whether to build dummy type module)
AC_ARG_ENABLE(mod-type-dummy,
	      AS_HELP_STRING([--enable-mod-type-dummy], [enable dummy type module]),
	      BUILD_MOD_UCMD_TYPE_DUMMY=$enableval,
	      BUILD_MOD_UCMD_TYPE_DUMMY=no)
AC_MSG_RESULT($BUILD_MOD_UCMD_TYPE_DUMMY)
if test x$BUILD_MOD_UCMD_TYPE_DUMMY = xyes; then
	AC_DEFINE([MOD_UCMD_TYPE_DUMMY], 1, [Define to 1 to enable dummy type module.])
fi
AM_CONDITIONAL([BUILD_MOD_UCMD_TYPE_DUMMY], [test x$BUILD_MOD_UCMD_TYPE_DUMMY = xyes])

AC_SUBST([sysconfigdir])
AC_SUBST([systemdsystemunitdir])
AC_SUBST([udevrulesdir])

AC_OUTPUT
AM_CHECK_CMOCKA
