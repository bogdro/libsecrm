#
# LibSecRm - A library for secure removing files.
#	-- Makefile.am, part of the build system.
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

if LSR_TESTS_ENABLED

TESTS = lsrtest_banning lsrtest_creat lsrtest_fopens lsrtest_memory \
	lsrtest_opens lsrtest_truncate lsrtest_unlink lsrtest_other
check_PROGRAMS = lsrtest_banning lsrtest_creat lsrtest_fopens lsrtest_memory \
	lsrtest_opens lsrtest_truncate lsrtest_unlink lsrtest_other

#nobase_nodist_include_HEADERS = lsrtest_common.h
EXTRA_DIST = lsrtest_common.h
LSRTEST_COMMON_SRC = lsrtest_common.c lsrtest_common.h
LSRTEST_COMMON_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
LSRTEST_COMMON_LIB = $(top_builddir)/src/libsecrm.la @CHECK_LIBS@ @LIBS@

lsrtest_banning_SOURCES = lsrtest_banning.c $(LSRTEST_COMMON_SRC)
lsrtest_banning_CFLAGS = $(LSRTEST_COMMON_CFLAGS)
lsrtest_banning_LDADD = $(LSRTEST_COMMON_LIB)

lsrtest_creat_SOURCES = lsrtest_creat.c $(LSRTEST_COMMON_SRC)
lsrtest_creat_CFLAGS = $(LSRTEST_COMMON_CFLAGS)
lsrtest_creat_LDADD = $(LSRTEST_COMMON_LIB)

lsrtest_fopens_SOURCES = lsrtest_fopens.c $(LSRTEST_COMMON_SRC)
lsrtest_fopens_CFLAGS = $(LSRTEST_COMMON_CFLAGS)
lsrtest_fopens_LDADD = $(LSRTEST_COMMON_LIB)

lsrtest_memory_SOURCES = lsrtest_memory.c $(LSRTEST_COMMON_SRC)
lsrtest_memory_CFLAGS = $(LSRTEST_COMMON_CFLAGS)
lsrtest_memory_LDADD = $(LSRTEST_COMMON_LIB)

lsrtest_opens_SOURCES = lsrtest_opens.c $(LSRTEST_COMMON_SRC)
lsrtest_opens_CFLAGS = $(LSRTEST_COMMON_CFLAGS)
lsrtest_opens_LDADD = $(LSRTEST_COMMON_LIB)

lsrtest_truncate_SOURCES = lsrtest_truncate.c $(LSRTEST_COMMON_SRC)
lsrtest_truncate_CFLAGS = $(LSRTEST_COMMON_CFLAGS)
lsrtest_truncate_LDADD = $(LSRTEST_COMMON_LIB)

lsrtest_unlink_SOURCES = lsrtest_unlink.c $(LSRTEST_COMMON_SRC)
lsrtest_unlink_CFLAGS = $(LSRTEST_COMMON_CFLAGS)
lsrtest_unlink_LDADD = $(LSRTEST_COMMON_LIB)

lsrtest_other_SOURCES = lsrtest_other.c $(LSRTEST_COMMON_SRC)
lsrtest_other_CFLAGS = $(LSRTEST_COMMON_CFLAGS)
lsrtest_other_LDADD = $(LSRTEST_COMMON_LIB)

x-compile: $(TESTS)
.PHONY: x-compile

endif
