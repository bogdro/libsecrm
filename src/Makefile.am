#
# LibSecRm - A library for secure removing files.
#	-- Makefile.am, part of the build system.
#
# Copyright (C) 2007-2024 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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

lib_LTLIBRARIES = libsecrm.la
libsecrm_la_SOURCES = libsecrm.c lsr_opens.c lsr_truncate.c lsr_unlink.c \
	lsr_creat.c lsr_banning.c lsr_memory.c lsr_wiping.c
EXTRA_DIST = lsr_cfg.h.in libsecrm.h.in lsr_public.c.in lsr_priv.h.in \
	randomize_names_gawk.sh randomize_names_perl.sh banning-generic.c

# VERSION = C:R:A     (current, revision, age)
# only code changed => R++
# interface changed => C++, R:=0
# - interface add => A++
# - interface removed => A:=0
libsecrm_la_LDFLAGS = -version-info 12:0:1


BUILT_SOURCES = lsr_paths.h
nobase_nodist_include_HEADERS = libsecrm.h
nodist_libsecrm_la_SOURCES = lsr_paths.h lsr_priv.h libsecrm.h
libsecrm_la_DISTCLEANFILES = lsr_paths.h lsr_priv.h libsecrm.h
lsr_paths.h: Makefile
	echo '#define SYSCONFDIR "$(sysconfdir)"' > lsr_paths.h

if PUBLIC_INTERFACE
nodist_libsecrm_la_SOURCES += lsr_public.c
libsecrm_la_DISTCLEANFILES += lsr_public.c
endif

x-randomnames: clean
	./randomize_names_gawk.sh

.PHONY: x-randomnames
