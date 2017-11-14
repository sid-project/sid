#!/bin/sh

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

DIE=0

(autoreconf --version) > /dev/null 2>&1 || {
        echo
        echo "Autoreconf utility not found."
        echo "The autoreconf utility is part of autoconf package."
        echo
        DIE=1
}

(automake --version) > /dev/null 2>&1 || {
        echo
        echo "Automake utility not found."
        DIE=1
}

test "$DIE" -eq "1" && exit 1

echo
echo "Updating configuration files..."

autoreconf --force --install

echo
echo "Now use 'configure' and 'make' to compile the source tree..."
