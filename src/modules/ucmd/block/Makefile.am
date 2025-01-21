#
# SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

SUBDIRS =

if BUILD_MOD_UCMD_BLOCK_BLKID
SUBDIRS += blkid
endif

if BUILD_MOD_UCMD_BLOCK_DM_MPATH
SUBDIRS += dm_mpath
endif

if BUILD_MOD_UCMD_BLOCK_DUMMY
SUBDIRS += dummy_block
endif

uninstall-hook:
	test -d ${DESTDIR}${pkglibdir}/modules/ucmd/block && rmdir ${DESTDIR}${pkglibdir}/modules/ucmd/block || true
