lib_LTLIBRARIES = libsecrm.la
libsecrm_la_SOURCES = libsecrm.c lsr_cfg.h libsecrm-priv.h lsr_opens.c lsr_truncate.c lsr_unlink.c \
	lsr_creat.c lsr_public.c lsr_banning.c

# VERSION = C:R:A     (current, revision, age)
# only code changed => R++
# interface changed => C++, R:=0
# - interface add => A++
# - interface removed => A:=0
libsecrm_la_LDFLAGS = -version-info 2:1:1

nobase_include_HEADERS = libsecrm.h

BUILT_SOURCES = lsr_paths.h
nodist_libsecrm_la_SOURCES = lsr_paths.h
libsecrm_la_DISTCLEANFILES = lsr_paths.h
lsr_paths.h: Makefile
	echo '#define SYSCONFDIR "$(sysconfdir)"' > lsr_paths.h

#if ISGCC
#AM_CFLAGS = 	-Wall -Wextra -Wfloat-equal -Wbad-function-cast		\
#		-Wsign-compare -Wunreachable-code -Wpointer-arith	\
#		-Wcast-qual -Wcast-align -Wstrict-prototypes 		\
#		-Wformat-security -Wformat-nonliteral -Wnested-externs	\
#		-Wshadow -Wconversion -Wdeclaration-after-statement	\
#		-Wundef -Wpadded -Wredundant-decls -Wfatal-errors	\
#		-pedantic -Wno-strict-aliasing
#if HAS_LL
# AM_CFLAGS += -std=gnu99
#endif
#endif

