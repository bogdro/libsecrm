/*
 * A library for secure removing data.
 *
 * Copyright (C) 2007-2021 Bogdan Drozdowski, bogdro (at) users . sourceforge . net
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
 * - The authors of the "fuser" utility, parts of which are used here. Fuser is:
 *	Based on fuser.c Copyright (C) 1993-2005 Werner Almesberger and Craig Small
 *	Completely re-written
 *	Copyright (C) 2005 Craig Small
 *
 */

#include "lsr_cfg.h"

#if (defined HAVE_DLFCN_H) && ((defined HAVE_DLSYM) || (defined HAVE_LIBDL))
	/* need RTLD_NEXT and dlvsym(), so define _GNU_SOURCE */
# ifndef _GNU_SOURCE
#  define _GNU_SOURCE	1
# endif
# include <dlfcn.h>
# ifndef RTLD_NEXT
#  define RTLD_NEXT ((void *) -1l)
# endif
#else
# ifdef LSR_ANSIC
#  error Dynamic loading functions missing.
# endif
#endif

#include <stdio.h>

	/* time() for randomization purposes */
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  ifdef HAVE_TIME_H
#   include <time.h>
#  endif
# endif
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* random(), srandom(), rand(), srand() */
#endif

#ifdef HAVE_STRING_H
# if (!defined STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

#include "lsr_priv.h"

static int	__lsr_is_initialized	= LSR_INIT_STAGE_NOT_INITIALIZED;

/* Pointers to original functions */
static i_cp		__lsr_real_unlink		= NULL;
static i_cp		__lsr_real_remove		= NULL;
static i_i_cp_i		__lsr_real_unlinkat		= NULL;
static i_cp		__lsr_real_rmdir		= NULL;

static i_cp_o64		__lsr_real_truncate64		= NULL;
static i_i_o64		__lsr_real_ftruncate64		= NULL;
static fp_cp_cp		__lsr_real_fopen64		= NULL;
static fp_cp_cp_fp	__lsr_real_freopen64		= NULL;
static i_cp_i_		__lsr_real_open64		= NULL;
static i_i_cp_i_	__lsr_real_openat64		= NULL;
static i_cp_mt		__lsr_real_creat64		= NULL;

static i_cp_o		__lsr_real_truncate		= NULL;
static i_i_o		__lsr_real_ftruncate		= NULL;
static fp_cp_cp		__lsr_real_fopen		= NULL;
static fp_cp_cp_fp	__lsr_real_freopen		= NULL;
static i_cp_i_		__lsr_real_open			= NULL;
static i_i_cp_i_	__lsr_real_openat		= NULL;
static i_cp_mt		__lsr_real_creat		= NULL;
static i_o_o		__lsr_real_posix_fallocate	= NULL;
static i_o64_o64	__lsr_real_posix_fallocate64	= NULL;
static i_i_i_o_o	__lsr_real_fallocate		= NULL;

/* memory-related functions: */
static f_s		__lsr_real_malloc		= NULL;
static vpp_s_s		__lsr_real_psx_memalign		= NULL;
static f_s		__lsr_real_valloc		= NULL;
static f_s		__lsr_real_pvalloc		= NULL;
static f_s_s		__lsr_real_memalign		= NULL;
static f_s_s		__lsr_real_aligned_alloc	= NULL;
static f_vp		__lsr_real_brk			= NULL;
static f_ip		__lsr_real_sbrk			= NULL;

#ifdef TEST_COMPILE
# undef LSR_ANSIC
#endif

/* =============================================================== */

#if (defined __STRICT_ANSI__) || (!defined HAVE_SRANDOM) || (!defined HAVE_RANDOM)

static unsigned long int __lsr_next = 0xdeafface;

/* 'man rand': */
int __lsr_rand (LSR_VOID)
{
	__lsr_next = __lsr_next * 1103515245 + 12345;
	return ((unsigned int)(__lsr_next/65536) % 32768);
}

static void __lsr_srand (
# ifdef LSR_ANSIC
	unsigned int seed)
# else
	seed)
	unsigned int seed;
# endif
{
	__lsr_next = seed;
}
#endif

/* =============================================================== */

void __lsr_copy_string (
#ifdef LSR_ANSIC
	char * const dest, const char src[], const size_t len)
#else
	dest, src, len)
	char * const dest;
	const char src[];
	const size_t len;
#endif
{
#if (!defined HAVE_STRING_H) && (!defined HAVE_MEMCPY)
	size_t i;
#endif
	if ( (src == NULL) || (dest == NULL) )
	{
		return;
	}
#ifdef HAVE_STRING_H
	strncpy (dest, src, len);
#else
# if defined HAVE_MEMCPY
	memcpy (dest, src, len);
# else
	for ( i = 0; i < len; i++ )
	{
		dest[i] = src[i];
	}
# endif
#endif
	dest[len] = '\0';
}

/* =============================================================== */

#ifndef HAVE_MEMCPY
void __lsr_memcopy (
# ifdef LSR_ANSIC
	void * const dest, const void * const src, const size_t len)
# else
	dest, src, len)
	void * const dest;
	const void * const src;
	const size_t len;
# endif
{
	size_t i;
	char * const d = (char *)dest;
	const char * const s = (const char *)src;

	for ( i = 0; i < len; i++ )
	{
		d[i] = s[i];
	}
}
#endif

/* =============================================================== */

#ifndef HAVE_MEMSET
void __lsr_mem_set (
# ifdef LSR_ANSIC
	void * const dest, const char value, const size_t len)
# else
	dest, value, len)
	void * const dest;
	const char value;
	const size_t len;
# endif
{
	size_t i;
	for ( i = 0; i < len; i++ )
	{
		((char *)dest)[i] = value;
	}
}
#endif

/* =============================================================== */

#if ((defined HAVE_DLSYM) || (defined HAVE_LIBDL_DLSYM))		\
	&& (!defined HAVE_DLVSYM) && (!defined HAVE_LIBDL_DLVSYM)	\
	|| (defined __GLIBC__ && (__GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 1)))
# define LSR_CANT_USE_VERSIONED_FOPEN 1
/*# warning Versioned fopen is unavailable, so LibSecRm may crash on some glibc versions.*/
#else
# undef LSR_CANT_USE_VERSIONED_FOPEN
#endif

/* =============================================================== */

int LSR_ATTR ((constructor))
__lsr_main (LSR_VOID)
{
	if ( __lsr_is_initialized == LSR_INIT_STAGE_NOT_INITIALIZED )
	{
		__lsr_set_internal_function (1);
		/* Get pointers to the original functions: */

		*(void **) (&__lsr_real_unlink)			= dlsym  (RTLD_NEXT, "unlink");
		*(void **) (&__lsr_real_remove)			= dlsym  (RTLD_NEXT, "remove");
		*(void **) (&__lsr_real_unlinkat)		= dlsym  (RTLD_NEXT, "unlinkat");
		*(void **) (&__lsr_real_rmdir)			= dlsym  (RTLD_NEXT, "rmdir");
		/* Libtrash: funny interaction fixed! when dlsym() was used instead of dlvsym(),
		   GNU libc would give us a pointer to an older version of fopen() and
		   subsequently crash if the calling code tried to use, e.g., getwc().
		   YES, THIS MUST BE 2.1 !
		   */
#ifdef LSR_CANT_USE_VERSIONED_FOPEN
		*(void **) (&__lsr_real_fopen64)		= dlsym  (RTLD_NEXT, "fopen64");
#else
		*(void **) (&__lsr_real_fopen64)		= dlvsym (RTLD_NEXT, "fopen64", "GLIBC_2.1");
		if ( __lsr_real_fopen64 == NULL )
		{
			*(void **) (&__lsr_real_fopen64)	= dlsym (RTLD_NEXT, "fopen64");
		}
#endif
		*(void **) (&__lsr_real_freopen64)		= dlsym  (RTLD_NEXT, "freopen64");
		*(void **) (&__lsr_real_open64)			= dlsym  (RTLD_NEXT, "open64");
		*(void **) (&__lsr_real_openat64)		= dlsym  (RTLD_NEXT, "openat64");

		*(void **) (&__lsr_real_truncate64)		= dlsym  (RTLD_NEXT, "truncate64");
		*(void **) (&__lsr_real_ftruncate64)		= dlsym  (RTLD_NEXT, "ftruncate64");
		*(void **) (&__lsr_real_creat64)		= dlsym  (RTLD_NEXT, "creat64");
#ifdef LSR_CANT_USE_VERSIONED_FOPEN
		*(void **) (&__lsr_real_fopen)			= dlsym  (RTLD_NEXT, "fopen");
#else
		*(void **) (&__lsr_real_fopen)			= dlvsym (RTLD_NEXT, "fopen", "GLIBC_2.1");
		if ( __lsr_real_fopen == NULL )
		{
			*(void **) (&__lsr_real_fopen)		= dlsym  (RTLD_NEXT, "fopen");
		}
#endif
		*(void **) (&__lsr_real_freopen)		= dlsym  (RTLD_NEXT, "freopen");
		*(void **) (&__lsr_real_open)			= dlsym  (RTLD_NEXT, "open");
		*(void **) (&__lsr_real_openat)			= dlsym  (RTLD_NEXT, "openat");

		*(void **) (&__lsr_real_truncate)		= dlsym  (RTLD_NEXT, "truncate");
		*(void **) (&__lsr_real_ftruncate)		= dlsym  (RTLD_NEXT, "ftruncate");
		*(void **) (&__lsr_real_creat)			= dlsym  (RTLD_NEXT, "creat");
		*(void **) (&__lsr_real_posix_fallocate)	= dlsym  (RTLD_NEXT, "posix_fallocate");
		*(void **) (&__lsr_real_posix_fallocate64)	= dlsym  (RTLD_NEXT, "posix_fallocate64");
		*(void **) (&__lsr_real_fallocate)		= dlsym  (RTLD_NEXT, "fallocate");

		/* memory-related functions: */
		*(void **) (&__lsr_real_malloc)			= dlsym  (RTLD_NEXT, "malloc");
		*(void **) (&__lsr_real_psx_memalign)		= dlsym  (RTLD_NEXT, "posix_memalign");
		*(void **) (&__lsr_real_valloc)			= dlsym  (RTLD_NEXT, "valloc");
		*(void **) (&__lsr_real_pvalloc)		= dlsym  (RTLD_NEXT, "pvalloc");
		*(void **) (&__lsr_real_memalign)		= dlsym  (RTLD_NEXT, "memalign");
		*(void **) (&__lsr_real_aligned_alloc)		= dlsym  (RTLD_NEXT, "aligned_alloc");
		*(void **) (&__lsr_real_brk)			= dlsym  (RTLD_NEXT, "brk");
		*(void **) (&__lsr_real_sbrk)			= dlsym  (RTLD_NEXT, "sbrk");


#if (!defined __STRICT_ANSI__) && (defined HAVE_SRANDOM) && (defined HAVE_RANDOM)
# if (defined HAVE_TIME_H) || (defined HAVE_SYS_TIME_H) || (defined TIME_WITH_SYS_TIME)
		srandom (0xdeafface * ((unsigned int) time (NULL) & 0x0FFFFFFFF));
# else
		srandom (0xdeafface);
# endif

#else

# if (defined HAVE_TIME_H) || (defined HAVE_SYS_TIME_H) || (defined TIME_WITH_SYS_TIME)
		__lsr_srand(0xdeafface * ((unsigned int) time (NULL) & 0x0FFFFFFFF));
		/*srand (0xdeafface*(unsigned long int) time (NULL));*/
# else
		__lsr_srand(0xdeafface);
		/*srand (0xdeafface);*/
# endif
#endif
		__lsr_set_internal_function (0);
		__lsr_is_initialized = LSR_INIT_STAGE_FULLY_INITIALIZED;
	}
	return 0;
}

/* =============================================================== */
/* Functions returning pointers to real functions, so that the variables
   can't be overwritten by user code with dlsym(): */
/* =============================================================== */

i_cp		__lsr_real_unlink_location (LSR_VOID)
{
	return __lsr_real_unlink;
}

/* =============================================================== */

i_cp		__lsr_real_remove_location (LSR_VOID)
{
	return __lsr_real_remove;
}

/* =============================================================== */

i_i_cp_i	__lsr_real_unlinkat_location (LSR_VOID)
{
	return __lsr_real_unlinkat;
}

/* =============================================================== */

i_cp		__lsr_real_rmdir_location (LSR_VOID)
{
	return __lsr_real_rmdir;
}


/* =============================================================== */

fp_cp_cp	__lsr_real_fopen64_location (LSR_VOID)
{
	return __lsr_real_fopen64;
}

/* =============================================================== */

fp_cp_cp_fp	__lsr_real_freopen64_location (LSR_VOID)
{
	return __lsr_real_freopen64;
}

/* =============================================================== */

i_cp_i_		__lsr_real_open64_location (LSR_VOID)
{
	return __lsr_real_open64;
}

/* =============================================================== */

i_i_cp_i_	__lsr_real_openat64_location (LSR_VOID)
{
	return __lsr_real_openat64;
}

/* =============================================================== */

i_cp_o64	__lsr_real_truncate64_location (LSR_VOID)
{
	return __lsr_real_truncate64;
}

/* =============================================================== */

i_i_o64		__lsr_real_ftruncate64_location (LSR_VOID)
{
	return __lsr_real_ftruncate64;
}

/* =============================================================== */

i_cp_mt		__lsr_real_creat64_location (LSR_VOID)
{
	return __lsr_real_creat64;
}


/* =============================================================== */

fp_cp_cp	__lsr_real_fopen_location (LSR_VOID)
{
	return __lsr_real_fopen;
}

/* =============================================================== */

fp_cp_cp_fp	__lsr_real_freopen_location (LSR_VOID)
{
	return __lsr_real_freopen;
}

/* =============================================================== */

i_cp_i_		__lsr_real_open_location (LSR_VOID)
{
	return __lsr_real_open;
}

/* =============================================================== */

i_i_cp_i_	__lsr_real_openat_location (LSR_VOID)
{
	return __lsr_real_openat;
}

/* =============================================================== */

i_cp_o		__lsr_real_truncate_location (LSR_VOID)
{
	return __lsr_real_truncate;
}

/* =============================================================== */

i_i_o		__lsr_real_ftruncate_location (LSR_VOID)
{
	return __lsr_real_ftruncate;
}

/* =============================================================== */

i_cp_mt		__lsr_real_creat_location (LSR_VOID)
{
	return __lsr_real_creat;
}


/* =============================================================== */

i_o_o		__lsr_real_posix_fallocate_location (LSR_VOID)
{
	return __lsr_real_posix_fallocate;
}

/* =============================================================== */

i_o64_o64	__lsr_real_posix_fallocate64_location (LSR_VOID)
{
	return __lsr_real_posix_fallocate64;
}

/* =============================================================== */

i_i_i_o_o	__lsr_real_fallocate_location (LSR_VOID)
{
	return __lsr_real_fallocate;
}

/* =============================================================== */
/* memory-related functions: */
/* =============================================================== */

f_s		__lsr_real_malloc_location (LSR_VOID)
{
	return __lsr_real_malloc;
}

/* =============================================================== */

vpp_s_s		__lsr_real_psx_memalign_location (LSR_VOID)
{
	return __lsr_real_psx_memalign;
}

/* =============================================================== */

f_s		__lsr_real_valloc_location (LSR_VOID)
{
	return __lsr_real_valloc;
}

/* =============================================================== */

f_s		__lsr_real_pvalloc_location (LSR_VOID)
{
	return __lsr_real_pvalloc;
}

/* =============================================================== */

f_s_s		__lsr_real_memalign_location (LSR_VOID)
{
	return __lsr_real_memalign;
}

/* =============================================================== */

f_s_s		__lsr_real_aligned_alloc_location (LSR_VOID)
{
	return __lsr_real_aligned_alloc;
}

/* =============================================================== */

f_vp		__lsr_real_brk_location (LSR_VOID)
{
	return __lsr_real_brk;
}

/* =============================================================== */

f_ip		__lsr_real_sbrk_location (LSR_VOID)
{
	return __lsr_real_sbrk;
}
