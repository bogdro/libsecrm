lib_LTLIBRARIES = libsecrm.la
#noinst_LIBRARIES = libsecrm.a
libsecrm_la_SOURCES = libsecrm.c lsr_cfg.h libsecrm.h lsr_opens.c lsr_truncate.c \
	lsr_unlink.c
libsecrm_la_LDFLAGS = -version-info 0:2:0

if ISGCC
AM_CFLAGS = 	-Wall -Wextra -Wfloat-equal -Wbad-function-cast		\
		-Wsign-compare -Wunreachable-code -Wpointer-arith	\
		-Wcast-qual -Wcast-align -Wstrict-prototypes 		\
		-Wformat-security -Wformat-nonliteral -Wnested-externs	\
		-Wshadow -Wconversion -Wdeclaration-after-statement	\
		-Wundef -Wpadded -Wredundant-decls -Wfatal-errors	\
		-pedantic
if HAS_LL
 AM_CFLAGS += -std=gnu99
endif
endif

