if LSR_TESTS_ENABLED

TESTS = lsrtest
check_PROGRAMS = lsrtest
lsrtest_SOURCES = lsrtest.c
lsrtest_CFLAGS = @CHECK_CFLAGS@ -I $(top_builddir)/src
lsrtest_LDADD = $(top_builddir)/src/libsecrm.la @CHECK_LIBS@ @LIBS@

endif
