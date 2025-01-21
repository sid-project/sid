#!/bin/sh

#
# SPDX-FileCopyrightText: (C) 2017-2025 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

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
