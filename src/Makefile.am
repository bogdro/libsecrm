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
libsecrm_la_LDFLAGS = -version-info 8:4:0


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

randomnames: clean
	./randomize_names_gawk.sh
