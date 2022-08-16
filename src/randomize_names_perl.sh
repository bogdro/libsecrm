#!/bin/sh

#
# A library for hiding local IP address.
#	-- a name randomizing script that uses Perl.
#
# Copyright (C) 2007-2019 Bogdan Drozdowski, bogdandr (at) op.pl
# License: GNU General Public License, v3+
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foudation:
#		Free Software Foundation
#		51 Franklin Street, Fifth Floor
#		Boston, MA 02110-1301
#		USA
#

# Change this to whatever you wish (but it has to start with a letter or a '_')
NEWNAMEPREFIX=__printf

for i in `perl -ne 'if (/(__lsr[a-zA-Z0-9_]+)/o) {my $m=$1; if (! /^((\/\*)|#)/o) {print "$m\n";}}' \
	 *.c *.h *.c.in *.h.in | sort -u`; do

	sed -i "s/\b$i\b/$NEWNAMEPREFIX$RANDOM$RANDOM$RANDOM/g" *;
done
