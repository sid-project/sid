##############################################################################
# This file is part of SID.
#
# Copyright (C) 2019 Red Hat, Inc. All rights reserved.
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

dist_systemdsystemunit_DATA = sid.socket \
			      sid.service

dist_sysconfig_DATA = sid.sysconfig

$(dist_systemdsystemunit_DATA):%:%.in
	$(SED) -e "s|(BINDIR)|$(bindir)|" \
	       -e "s|(SYSCONFIGDIR)|$(sysconfigdir)|" \
	       $< >$@

$(dist_sysconfig_DATA):%:%.in
	$(SED) -e "s|(SYSTEMDSYSTEMUNITDIR)|$(systemdsystemunitdir)|" $< >$@

distclean-local:
	$(RM) $(dist_systemdsystemunit_DATA) \
		$(dist_sysconfig_DATA)
