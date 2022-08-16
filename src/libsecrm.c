/*
 * A library for secure removing files.
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
 * License: GNU General Public License, v3+
 *
 * Syntax example: export LD_PRELOAD=/usr/local/lib/libsecrm.so
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foudation:
 *		Free Software Foundation
 *		51 Franklin Street, Fifth Floor
 *		Boston, MA 02110-1301
 *		USA
 *
 * Thanks to:
 * - Manuel Arriaga for libtrash, parts of which are used here
 * - Colin Plumb, for the great 'shred' program, parts of which are used here.
 *   The 'shred' utility is:
 *	Copyright (C) 1999-2006 Free Software Foundation, Inc.
 *	Copyright (C) 1997, 1998, 1999 Colin Plumb.
 * - The authors of Libsafe for the great piece of software, parts of which
 *   are used here. Libsafe is:
 *	Copyright (C) 2002 Avaya Labs, Avaya Inc.
 *	Copyright (C) 1999 Bell Labs, Lucent Technologies.
 *	Copyright (C) Arash Baratloo, Timothy Tsai, and Navjot Singh.
 */

#include "lsr_cfg.h"
#include "lsr_paths.h"

#if (defined HAVE_DLFCN_H) && (defined HAVE_LIBDL)
	/* need RTLD_NEXT and dlvsym(), so define _GNU_SOURCE */
# define _GNU_SOURCE	1
# include <dlfcn.h>
# ifndef RTLD_NEXT
#  define RTLD_NEXT ((void *) -1l)
# endif
#else
# error Dynamic loading functions missing.
#endif

#include <stdio.h>

#ifdef HAVE_STRING_H
# if (!STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#ifdef HAVE_TIME_H
# include <time.h>	/* time() for randomization purposes */
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* random(), srandom(), rand(), srand() */
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#include "libsecrm.h"

int	is_initialized		= 0;

/* Pointers to original functions */
i_cp		__lsr_real_unlink	= NULL, __lsr_real_remove	= NULL;
i_i_cp_i	__lsr_real_unlinkat	= NULL;

i_cp_o64	__lsr_real_truncate64	= NULL;
i_i_o64		__lsr_real_ftruncate64	= NULL;
fp_cp_cp	__lsr_real_fopen64	= NULL;
fp_cp_cp_fp	__lsr_real_freopen64	= NULL;
i_cp_i_		__lsr_real_open64	= NULL;
i_i_cp_i_	__lsr_real_openat64	= NULL;

i_cp_o		__lsr_real_truncate	= NULL;
i_i_o		__lsr_real_ftruncate	= NULL;
fp_cp_cp	__lsr_real_fopen	= NULL;
fp_cp_cp_fp	__lsr_real_freopen	= NULL;
i_cp_i_		__lsr_real_open		= NULL;
i_i_cp_i_	__lsr_real_openat	= NULL;

#if (defined __STRICT_ANSI__) || (!defined HAVE_SRANDOM) || (!defined HAVE_RANDOM)

static unsigned long next = 0xdeafface;

/* 'man rand': */
int __lsr_rand (void) {
	next = next * 1103515245 + 12345;
	return ((unsigned)(next/65536) % 32768);
}

static void __lsr_srand (unsigned seed) {
	next = seed;
}
#endif

/* =============================================================== */
/*
typedef ssize_t (*yyy) (int fd, const void *buf, size_t count);
yyy __lsr_orig_write = NULL;
typedef ssize_t (*zzz) (int fd, void *buf, size_t count);
zzz __lsr_orig_read = NULL;

typedef void* (*www) (void *start, size_t length, int prot, int flags,
                  int fd, off_t offset);
www __lsr_orig_mmap = NULL;

typedef int (*ttt) (int);
ttt __lsr_orig_close = NULL;

ssize_t write(int fd, const void *buf, size_t count) {

	fprintf(stderr, "lsr:write(%d, %x, %lu)\n", fd, (unsigned long)buf, count);
	fflush(stderr);
	return (*__lsr_orig_write) (fd, buf, count);
}

ssize_t read(int fd, void *buf, size_t count) {

	fprintf(stderr, "lsr:read(%d, %x, %lu)\n", fd, (unsigned long)buf, count);
	fflush(stderr);
	return (*__lsr_orig_read) (fd, buf, count);
}

void *mmap(void *start, size_t length, int prot, int flags,
                  int fd, off_t offset) {

	fprintf(stderr, "lsr:mmap(%x, %ud, %d, %d, %d, %lu)\n", (unsigned long)start,
		length, prot, flags, fd, offset);
	fflush(stderr);
	return (*__lsr_orig_mmap) (start, length, prot, flags, fd, offset);
}

int close(int fd)
{
	fprintf(stderr, "lsr:close(%d)\n", fd);
	fflush(stderr);
	return (*__lsr_orig_close) (fd);
}
*/

/* Signal-related stuff */
volatile sig_atomic_t sig_recvd = 0;		/* non-zero after signal received */

/* ================================================================== */

int LSR_ATTR ((constructor))
__lsr_main (void)
{
#ifdef HAVE_ERRNO_H
	int err;
#endif

	if ( is_initialized == 0 )
	{
#ifdef HAVE_ERRNO_H
		err = 0;
#endif
/*
		*(void**) (&__lsr_orig_write) = dlsym(RTLD_NEXT, "write");
		*(void**) (&__lsr_orig_read) = dlsym(RTLD_NEXT, "read");
		*(void**) (&__lsr_orig_mmap) = dlsym(RTLD_NEXT, "mmap");
		*(void**) (&__lsr_orig_close) = dlsym(RTLD_NEXT, "close");
*/
		/* Get pointers to the original functions: */

		*(void **) (&__lsr_real_unlink)      = dlsym  (RTLD_NEXT, "unlink");
		*(void **) (&__lsr_real_remove)      = dlsym  (RTLD_NEXT, "remove");
		*(void **) (&__lsr_real_unlinkat)    = dlsym  (RTLD_NEXT, "unlinkat");
		/* funny interaction fixed! when dlsym() was used instead of dlvsym(),
		   GNU libc would give us a pointer to an older version of fopen() and
		   subsequently crash if the calling code tried to use, e.g., getwc().
		   YES, THIS MUST BE 2.1 !
		   */
# if (defined HAVE_DLSYM) && (!defined HAVE_DLVSYM)	\
	|| ( defined __GLIBC__ && (__GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 1) ) )
		*(void **) (&__lsr_real_fopen64)     = dlsym  (RTLD_NEXT, "fopen64");
# else
		*(void **) (&__lsr_real_fopen64)     = dlvsym (RTLD_NEXT, "fopen64", "GLIBC_2.1");
# endif
		*(void **) (&__lsr_real_freopen64)   = dlsym  (RTLD_NEXT, "freopen64");
		*(void **) (&__lsr_real_open64)      = dlsym  (RTLD_NEXT, "open64");
		*(void **) (&__lsr_real_openat64)    = dlsym  (RTLD_NEXT, "openat64");

		*(void **) (&__lsr_real_truncate64)  = dlsym  (RTLD_NEXT, "truncate64");
		*(void **) (&__lsr_real_ftruncate64) = dlsym  (RTLD_NEXT, "ftruncate64");
# if (defined HAVE_DLSYM) && (!defined HAVE_DLVSYM)	\
	|| ( defined __GLIBC__ && (__GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 1) ) )
		*(void **) (&__lsr_real_fopen)       = dlsym  (RTLD_NEXT, "fopen");
# else
		*(void **) (&__lsr_real_fopen)       = dlvsym (RTLD_NEXT, "fopen", "GLIBC_2.1");
# endif
		*(void **) (&__lsr_real_freopen)     = dlsym  (RTLD_NEXT, "freopen");
		*(void **) (&__lsr_real_open)        = dlsym  (RTLD_NEXT, "open");
		*(void **) (&__lsr_real_openat)      = dlsym  (RTLD_NEXT, "openat");

		*(void **) (&__lsr_real_truncate)    = dlsym  (RTLD_NEXT, "truncate");
		*(void **) (&__lsr_real_ftruncate)   = dlsym  (RTLD_NEXT, "ftruncate");

#if (!defined __STRICT_ANSI__) && (defined HAVE_SRANDOM) && (defined HAVE_RANDOM)
# ifdef HAVE_TIME_H
		srandom (0xdeafface*(unsigned long) time (NULL));
# else
		srandom (0xdeafface);
# endif

#else

# ifdef HAVE_TIME_H
		__lsr_srand(0xdeafface*(unsigned long) time (NULL));
		/*srand (0xdeafface*(unsigned long) time (NULL));*/
# else
		__lsr_srand(0xdeafface);
		/*srand (0xdeafface);*/
# endif
#endif
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
#ifdef HAVE_SIGNAL_H
		sig_recvd = 0;
#endif
		is_initialized = 1;
	}

	return 0;
}

#ifdef HAVE_SIGNAL_H
# ifndef RETSIGTYPE
#  define RETSIGTYPE void
#  undef RETSIG_ISINT
# endif
/**
 * Signal handler - Sets a flag which will stop further program operations, when a
 * signal which would normally terminate the program is received.
 * \param signum Signal number.
 */
RETSIGTYPE
fcntl_signal_received ( const int signum )
{

	sig_recvd = signum;
# ifdef RETSIG_ISINT
	return 0;
# endif
}
#endif

/******************* some of what's below comes from libsafe ***************/

static char *
__lsr_get_exename (char * const exename, const size_t size)
{
	ssize_t res;
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	/*
	 * get the name of the current executable
	 */
#ifdef HAVE_ERRNO_H
	err = errno;
#endif
#ifdef HAVE_READLINK
	res = readlink ("/proc/self/exe", exename, size - 1);
	if (res == -1)
	{
		exename[0] = '\0';
	}
	else
	{
		exename[res] = '\0';
	}
#else
	exename[0] = '\0';
#endif
#ifdef HAVE_ERRNO_H
	errno = err;
#endif
	return exename;
}

#define  MAXPATHLEN 4097


int LSR_ATTR ((warn_unused_result))
 __lsr_check_prog_ban (void)
{
	char    exename[MAXPATHLEN];	/* 4096 */
	char    omitfile[MAXPATHLEN];
	FILE    *fp;

	/*
	 * Is this process on the list of applications to ignore?  Note that
	 * programs listed in /etc/libsafe.exclude must be specified as absolute
	 * pathnames.
	 */
	__lsr_get_exename (exename, MAXPATHLEN);
	exename[MAXPATHLEN] = '\0';
	if ( strlen (exename) == 0 )
	{
		/* can't find executable name. Assume not banned */
		return 0;
	}
        fp = (*__lsr_real_fopen) (SYSCONFDIR "/libsecrm.progban", "r");
	if (fp!= NULL)
	{
		while ( fgets (omitfile, sizeof (omitfile), fp) != NULL )
		{
			omitfile[strnlen (omitfile, sizeof (omitfile)) - 1] = '\0';

			/*if (strncmp (omitfile, exename, sizeof (omitfile)) == 0)*/
			/* NOTE the reverse parameters */
			if (strstr (exename, omitfile) == 0)
			{
				return 1;	/* YES, this program is banned */
			}
		}

		fclose (fp);
	}
	return 0;	/* NO, this program is not banned */
}

int LSR_ATTR ((warn_unused_result))
__lsr_check_file_ban (const char * const name)
{
	char    omitfile[MAXPATHLEN];
	FILE    *fp;

	/* no filename means banned */
	if ( name == NULL )
	{
		return 1;
	}
	if ( strlen (name) == 0 )
	{
		return 1;
	}

        fp = (*__lsr_real_fopen) (SYSCONFDIR "/libsecrm.fileban", "r");
	if (fp != NULL)
	{
		while ( fgets (omitfile, sizeof (omitfile), fp) != NULL )
		{
			omitfile[strnlen (omitfile, sizeof (omitfile)) - 1] = '\0';

			/* NOTE the reverse parameters */
			if (strstr (name, omitfile) == 0)
			{
				return 1;	/* YES, this file is banned */
			}
		}

		fclose (fp);
	}
	return 0;	/* NO, this file is not banned */
}
