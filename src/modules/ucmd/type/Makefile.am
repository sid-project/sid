#
# SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

SUBDIRS =

if BUILD_MOD_UCMD_TYPE_DM
SUBDIRS += dm
endif

if BUILD_MOD_UCMD_TYPE_DUMMY
SUBDIRS += dummy_type
endif

uninstall-hook:
	test -d ${DESTDIR}${pkglibdir}/modules/ucmd/type && rmdir ${DESTDIR}${pkglibdir}/modules/ucmd/type || true
