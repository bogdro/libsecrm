/*
 * A library for secure removing files.
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
 * License: GNU General Public License, v2+
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
 *	The 'shred' utility is:
	   Copyright (C) 1999-2006 Free Software Foundation, Inc.
	   Copyright (C) 1997, 1998, 1999 Colin Plumb.
 *
 */

#include "lsr_cfg.h"
#include <stdio.h>

#if (defined HAVE_DLFCN_H) && (defined HAVE_LIBDL)
# define __USE_GNU	/* need RTLD_NEXT */
# include <dlfcn.h>
#else
# error Dynamic loading functions missing.
#endif

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
# include <stdlib.h>	/* strtoul(), random(), srandom(), rand(), srand() */
#endif

#include "libsecrm.h"

static int	is_initialized = 0;

i_cp		__lsr_real_unlink = NULL;
i_i_cp_i	__lsr_real_unlinkat = NULL;

i_cp_o		__lsr_real_truncate = NULL;
i_i_o		__lsr_real_ftruncate = NULL;
#ifdef __USE_FILE_OFFSET64
i_cp_o64	__lsr_real_truncate64 = NULL;
i_i_o64		__lsr_real_ftruncate64 = NULL;
#endif

fp_cp_cp	__lsr_real_fopen = NULL, __lsr_real_fopen64 = NULL;
fp_cp_cp_fp	__lsr_real_freopen = NULL, __lsr_real_freopen64 = NULL;
i_cp_i_		__lsr_real_open = NULL, __lsr_real_open64 = NULL;
fp_i_cp		__lsr_real_fdopen = NULL;
i_i_cp_i_	__lsr_real_openat = NULL, __lsr_real_openat64 = NULL;


/* =============================================================== */

int LSR_ATTR((constructor))
__lsr_main (void)
{

	if ( is_initialized == 0 ) {
		/* Get pointers to the original functions: */

		*(void **) (&__lsr_real_unlink)      = dlsym (RTLD_NEXT, "unlink");
		*(void **) (&__lsr_real_unlinkat)    = dlsym (RTLD_NEXT, "unlinkat");
		/* funny interaction fixed! when dlsym() was used instead of dlvsym(),
		   GNU libc would give us a pointer to an older version of fopen() and
		   subsequently crash if the calling code tried to use, e.g., getwc().
		   YES, THIS MUST BE 2.1 !
		   */
#ifdef __USE_FILE_OFFSET64
		*(void **) (&__lsr_real_fopen64)     = dlvsym (RTLD_NEXT, "fopen64", "GLIBC_2.1");
		*(void **) (&__lsr_real_freopen64)   = dlsym (RTLD_NEXT, "freopen64");
		*(void **) (&__lsr_real_open64)      = dlsym (RTLD_NEXT, "open64");
		*(void **) (&__lsr_real_openat64)    = dlsym (RTLD_NEXT, "openat64");

		*(void **) (&__lsr_real_truncate64)  = dlsym (RTLD_NEXT, "truncate64");
		*(void **) (&__lsr_real_ftruncate64) = dlsym (RTLD_NEXT, "ftruncate64");
#else
		*(void **) (&__lsr_real_fopen)       = dlvsym (RTLD_NEXT, "fopen", "GLIBC_2.1");
		*(void **) (&__lsr_real_freopen)     = dlsym (RTLD_NEXT, "freopen");
		*(void **) (&__lsr_real_open)        = dlsym (RTLD_NEXT, "open");
		*(void **) (&__lsr_real_fdopen)      = dlsym (RTLD_NEXT, "fdopen");
		*(void **) (&__lsr_real_openat)      = dlsym (RTLD_NEXT, "openat");

		*(void **) (&__lsr_real_truncate)    = dlsym (RTLD_NEXT, "truncate");
		*(void **) (&__lsr_real_ftruncate)   = dlsym (RTLD_NEXT, "ftruncate");
#endif

#if (!defined __STRICT_ANSI__) && (defined HAVE_SRANDOM)
# ifdef HAVE_TIME_H
		srandom (0xdeafface*(unsigned long) time (NULL));
# else
		srandom (0xdeafface);
# endif

#else

# ifdef HAVE_TIME_H
		srand (0xdeafface*(unsigned long) time (NULL));
# else
		srand (0xdeafface);
# endif
#endif
		is_initialized = 1;
	}

	return 0;
}
