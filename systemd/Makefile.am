#
# SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

dist_systemdsystemunit_DATA = sid.socket \
			      sid.service

dist_sysconfig_DATA = sid.sysconfig

$(dist_systemdsystemunit_DATA):%:%.in
	$(SED) -e "s|(SBINDIR)|$(sbindir)|" \
	       -e "s|(SYSCONFIGDIR)|$(sysconfigdir)|" \
	       $< >$@

$(dist_sysconfig_DATA):%:%.in
	$(SED) -e "s|(SYSTEMDSYSTEMUNITDIR)|$(systemdsystemunitdir)|" $< >$@

distclean-local:
	$(RM) $(dist_systemdsystemunit_DATA) \
		$(dist_sysconfig_DATA)

EXTRA_DIST = sid.socket.in \
	     sid.service.in \
	     sid.sysconfig.in
