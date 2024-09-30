#
# SPDX-FileCopyrightText: (C) 2017-2024 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

SUBDIRS = type block

uninstall-hook:
	test -d ${DESTDIR}${pkglibdir}/modules/ucmd && rmdir ${DESTDIR}${pkglibdir}/modules/ucmd || true
