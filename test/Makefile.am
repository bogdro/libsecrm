if LSR_TESTS_ENABLED

TESTS = lsrtest_banning lsrtest_creat lsrtest_fopens lsrtest_memory lsrtest_opens lsrtest_truncate lsrtest_unlink
check_PROGRAMS = lsrtest_banning lsrtest_creat lsrtest_fopens lsrtest_memory lsrtest_opens lsrtest_truncate lsrtest_unlink

#nobase_nodist_include_HEADERS = lsrtest_common.h
EXTRA_DIST = lsrtest_common.h

lsrtest_banning_SOURCES = lsrtest_banning.c lsrtest_common.c lsrtest_common.h
lsrtest_banning_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lsrtest_banning_LDADD = $(top_builddir)/src/libsecrm.la @CHECK_LIBS@ @LIBS@

lsrtest_creat_SOURCES = lsrtest_creat.c lsrtest_common.c lsrtest_common.h
lsrtest_creat_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lsrtest_creat_LDADD = $(top_builddir)/src/libsecrm.la @CHECK_LIBS@ @LIBS@

lsrtest_fopens_SOURCES = lsrtest_fopens.c lsrtest_common.c lsrtest_common.h
lsrtest_fopens_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lsrtest_fopens_LDADD = $(top_builddir)/src/libsecrm.la @CHECK_LIBS@ @LIBS@

lsrtest_memory_SOURCES = lsrtest_memory.c lsrtest_common.c lsrtest_common.h
lsrtest_memory_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lsrtest_memory_LDADD = $(top_builddir)/src/libsecrm.la @CHECK_LIBS@ @LIBS@

lsrtest_opens_SOURCES = lsrtest_opens.c lsrtest_common.c lsrtest_common.h
lsrtest_opens_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lsrtest_opens_LDADD = $(top_builddir)/src/libsecrm.la @CHECK_LIBS@ @LIBS@

lsrtest_truncate_SOURCES = lsrtest_truncate.c lsrtest_common.c lsrtest_common.h
lsrtest_truncate_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lsrtest_truncate_LDADD = $(top_builddir)/src/libsecrm.la @CHECK_LIBS@ @LIBS@

lsrtest_unlink_SOURCES = lsrtest_unlink.c lsrtest_common.c lsrtest_common.h
lsrtest_unlink_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lsrtest_unlink_LDADD = $(top_builddir)/src/libsecrm.la @CHECK_LIBS@ @LIBS@

endif
