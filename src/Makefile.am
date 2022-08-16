lib_LTLIBRARIES = libsecrm.la
libsecrm_la_SOURCES = libsecrm.c lsr_opens.c lsr_truncate.c lsr_unlink.c \
	lsr_creat.c lsr_public.c lsr_banning.c lsr_memory.c
EXTRA_DIST = lsr_cfg.h.in libsecrm.h.in lsr_public.c.in libsecrm-priv.h.in

# VERSION = C:R:A     (current, revision, age)
# only code changed => R++
# interface changed => C++, R:=0
# - interface add => A++
# - interface removed => A:=0
libsecrm_la_LDFLAGS = -version-info 3:0:2

nobase_include_HEADERS = libsecrm.h

BUILT_SOURCES = lsr_paths.h
nodist_libsecrm_la_SOURCES = lsr_paths.h
libsecrm_la_DISTCLEANFILES = lsr_paths.h
lsr_paths.h: Makefile
	echo '#define SYSCONFDIR "$(sysconfdir)"' > lsr_paths.h

