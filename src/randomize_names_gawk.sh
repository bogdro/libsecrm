#!/bin/sh

#
# A library for hiding local IP address.
#	-- a name randomizing script that uses GNU awk.
#
# Copyright (C) 2007-2022 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# Change this to whatever you wish (but it has to start with a letter or a '_')
NEWNAMEPREFIX=__scanf

for i in $(awk '{if (/(__lsr[a-zA-Z0-9_]+)/ && ! /^((\/\*)|#)/)
		{
			match ($0, /(__lsr[a-zA-Z0-9_]+)/, a);
			print a[1];
		}}' ./*.c ./*.c.in ./*.h ./*.h.in | sort -u); do

	sed -i "s/\b$i\b/$NEWNAMEPREFIX$RANDOM$RANDOM$RANDOM/g" ./*;
done
