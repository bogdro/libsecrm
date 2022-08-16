lib_LTLIBRARIES = libsecrm.la
libsecrm_la_SOURCES = libsecrm.c lsr_opens.c lsr_truncate.c lsr_unlink.c \
	lsr_creat.c lsr_banning.c lsr_memory.c
EXTRA_DIST = lsr_cfg.h.in libsecrm.h.in lsr_public.c.in libsecrm-priv.h.in \
	randomize_names_gawk.sh randomize_names_perl.sh

# VERSION = C:R:A     (current, revision, age)
# only code changed => R++
# interface changed => C++, R:=0
# - interface add => A++
# - interface removed => A:=0
libsecrm_la_LDFLAGS = -version-info 7:0:6


BUILT_SOURCES = lsr_paths.h
nodist_libsecrm_la_SOURCES = lsr_paths.h libsecrm-priv.h
libsecrm_la_DISTCLEANFILES = lsr_paths.h libsecrm-priv.h
lsr_paths.h: Makefile
	echo '#define SYSCONFDIR "$(sysconfdir)"' > lsr_paths.h

if PUBLIC_INTERFACE
nobase_include_HEADERS = libsecrm.h
nodist_libsecrm_la_SOURCES += lsr_public.c libsecrm.h
libsecrm_la_DISTCLEANFILES += lsr_public.c libsecrm.h
endif
