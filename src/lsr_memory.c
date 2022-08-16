/*
 * A library for secure removing files.
 *	-- memory management functions' replacements.
 *
 * Copyright (C) 2007-2013 Bogdan Drozdowski, bogdandr (at) op.pl
 * Parts of this file are Copyright (C) Free Software Foundation, Inc.
 * License: GNU General Public License, v3+
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
 */

#include "lsr_cfg.h"

#define _POSIX_C_SOURCE 200112L	/* posix_memalign() */
#define _BSD_SOURCE		/* brk(), sbrk(), better compatibility with OpenBSD */
#define _XOPEN_SOURCE 600	/* brk(), sbrk() */
#define _LARGEFILE64_SOURCE 1	/* off64_t in libsecrm-priv.h */

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>	/* brk(), sbrk(), sysconf(), getpagesize() */
#endif

#include "libsecrm-priv.h"	/* includes intptr_t */

#if (!defined __STRICT_ANSI__) && (defined HAVE_SRANDOM) && (defined HAVE_RANDOM)
# define __lsr_rand random
#endif

/* This is for marking that we already are in memory allocation functions,
to avoid endless loops */
static volatile int __lsr_internal_function = 0;

#ifndef HAVE_MEMALIGN
extern void *memalign LSR_PARAMS((size_t boundary, size_t size));
#endif
#ifndef HAVE_POSIX_MEMALIGN
extern int posix_memalign LSR_PARAMS((void **memptr, size_t alignment, size_t size));
#endif

/* ======================================================= */
/**
 * Tells if we're in a libsecrm's internal function.
 */
int
__lsr_get_internal_function (
#ifdef LSR_ANSIC
	void
#endif
)
{
	return __lsr_internal_function;
}

/* ======================================================= */

/**
 * Sets whether we're in a libsecrm's internal function.
 */
void
__lsr_set_internal_function (
#ifdef LSR_ANSIC
	int is_intrn)
#else
	is_intrn)
	int is_intrn;
#endif
{
	__lsr_internal_function = is_intrn;
}

/* ======================================================= */

void *
malloc (
#ifdef LSR_ANSIC
	size_t size)
#else
	size)
	size_t size;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	void * ret;
	int selected[LSR_NPAT] = {0};

	__lsr_main ();
#ifdef LSR_DEBUG
	if ( __lsr_get_internal_function () == 0 )
	{
		__lsr_set_internal_function (1);
		fprintf (stderr, "libsecrm: malloc (%u)\n", size);
		fflush (stderr);
		__lsr_set_internal_function (0);
	}
#endif

	if ( __lsr_real_malloc_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}
	if ( __lsr_get_internal_function () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_malloc_location ()) ( size );
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_malloc_location ()) ( size );
	}

	ret = (*__lsr_real_malloc_location ()) ( size );
	if ( ret != NULL )
	{
		__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
			ret, size, selected);
	}
	return ret;
}

/* ======================================================= */

int
posix_memalign (
#ifdef LSR_ANSIC
	void **memptr, size_t alignment, size_t size)
#else
	memptr, alignment, size)
	void **memptr;
	size_t alignment;
	size_t size;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	int ret;
	int selected[LSR_NPAT] = {0};

	__lsr_main ();
#ifdef LSR_DEBUG
	if ( __lsr_get_internal_function () == 0 )
	{
		__lsr_set_internal_function (1);
		fprintf (stderr, "libsecrm: posix_memalign (0x%x, %u, %u)\n",
			(unsigned int)memptr, alignment, size);
		fflush (stderr);
		__lsr_set_internal_function (0);
	}
#endif

	if ( __lsr_real_psx_memalign_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return -1;
	}
	if ( __lsr_get_internal_function () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_psx_memalign_location ()) ( memptr, alignment, size );
	}

	if ( memptr == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_psx_memalign_location ()) ( memptr, alignment, size );
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_psx_memalign_location ()) ( memptr, alignment, size );
	}

	ret = (*__lsr_real_psx_memalign_location ()) ( memptr, alignment, size );
	if ( ret == 0 )
	{
		__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
			*memptr, size, selected);
	}
	return ret;
}

/* ======================================================= */

void *
valloc (
#ifdef LSR_ANSIC
	size_t size)
#else
	size)
	size_t size;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	void *ret;
	int selected[LSR_NPAT] = {0};

	__lsr_main ();
#ifdef LSR_DEBUG
	if ( __lsr_get_internal_function () == 0 )
	{
		__lsr_set_internal_function (1);
		fprintf (stderr, "libsecrm: valloc (%u)\n", size);
		fflush (stderr);
		__lsr_set_internal_function (0);
	}
#endif

	if ( __lsr_real_valloc_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}
	if ( __lsr_get_internal_function () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_valloc_location ()) ( size );
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_valloc_location ()) ( size );
	}

	ret = (*__lsr_real_valloc_location ()) ( size );
	if ( ret != NULL )
	{
		__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
			ret, size, selected);
	}
	return ret;
}

/* ======================================================= */

void *
pvalloc (
#ifdef LSR_ANSIC
	size_t size)
#else
	size)
	size_t size;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	void *ret;
	int selected[LSR_NPAT] = {0};

	__lsr_main ();
#ifdef LSR_DEBUG
	if ( __lsr_get_internal_function () == 0 )
	{
		__lsr_set_internal_function (1);
		fprintf (stderr, "libsecrm: pvalloc (%u)\n", size);
		fflush (stderr);
		__lsr_set_internal_function (0);
	}
#endif

	if ( __lsr_real_pvalloc_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}
	if ( __lsr_get_internal_function () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_pvalloc_location ()) ( size );
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_pvalloc_location ()) ( size );
	}

	ret = (*__lsr_real_pvalloc_location ()) ( size );
	if ( ret != NULL )
	{
		/* round up to the nearest page boundary */
#ifdef HAVE_SYSCONF
		__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (), ret,
			(size_t)(size + ((size_t)sysconf(_SC_PAGESIZE)
			- (size % (size_t)sysconf(_SC_PAGESIZE)))), selected);
#else
# ifdef HAVE_GETPAGESIZE
		__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (), ret,
			(size_t)(size + ((size_t)getpagesize ()
			- (size % (size_t)getpagesize ()))), selected);
# else
		__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
			ret, size, selected);
# endif
#endif
	}
	return ret;
}

/* ======================================================= */

void *
memalign (
#ifdef LSR_ANSIC
	size_t boundary, size_t size)
#else
	boundary, size)
	size_t boundary;
	size_t size;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	void *ret;
	int selected[LSR_NPAT] = {0};

	__lsr_main ();
#ifdef LSR_DEBUG
	if ( __lsr_get_internal_function () == 0 )
	{
		__lsr_set_internal_function (1);
		fprintf (stderr, "libsecrm: memalign (%u, %u)\n", boundary, size);
		fflush (stderr);
		__lsr_set_internal_function (0);
	}
#endif

	if ( __lsr_real_memalign_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}
	if ( __lsr_get_internal_function () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_memalign_location ()) ( boundary, size );
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_memalign_location ()) ( boundary, size );
	}

	ret = (*__lsr_real_memalign_location ()) ( boundary, size );
	if ( ret != NULL )
	{
		__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
			ret, size, selected);
	}
	return ret;
}

/* ======================================================= */

BRK_RETTYPE
brk (
#ifdef LSR_ANSIC
	BRK_ARGTYPE end_data_segment)
#else
	end_data_segment)
	BRK_ARGTYPE end_data_segment;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	BRK_RETTYPE ret;
/* these defines allow checking the return type or parameter's type: */
#define const
#define int 1*
#define void 2
#define char 3
#if (BRK_RETTYPE 2 > 3 && SBRK_RETTYPE 2 > 3) || (BRK_RETTYPE 2 <= 3)
# undef int
# undef void
# undef char
# undef const
	SBRK_RETTYPE top;
	int selected[LSR_NPAT] = {0};
#else
# undef int
# undef void
# undef char
# undef const
#endif

	__lsr_main ();
#ifdef LSR_DEBUG
	if ( __lsr_get_internal_function () == 0 )
	{
		__lsr_set_internal_function (1);
		fprintf (stderr, "libsecrm: brk (0x%x)\n", (unsigned int)end_data_segment);
		fflush (stderr);
		__lsr_set_internal_function (0);
	}
#endif

	if ( (__lsr_real_brk_location () == NULL) || (__lsr_real_sbrk_location () == NULL) )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
/* these defines allow checking the return type or parameter's type: */
#define const
#define int 1*
#define void 2
#define char 3
#if BRK_RETTYPE 2 > 3
		/* return type is a pointer (new program break) */
		return NULL;
#else
		/* return type is an integral type */
		return -1;
#endif
#undef int
#undef void
#undef char
#undef const
	}
	if ( __lsr_get_internal_function () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_brk_location ()) ( end_data_segment );
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_brk_location ()) ( end_data_segment );
	}

/* these defines allow checking the return type or parameter's type: */
#define const
#define int 1*
#define void 2
#define char 3
#if BRK_RETTYPE 2 > 3
	/* return type is a pointer (new program break) */
# if SBRK_RETTYPE 2 > 3
#  undef int
#  undef void
#  undef char
#  undef const
	/* sbrk() returns a pointer */
	top = (*__lsr_real_sbrk_location ()) ((SBRK_ARGTYPE)0);
	if ( end_data_segment > top )
	{
		/* allocation */
		ret = (*__lsr_real_brk_location ()) ( end_data_segment );
		if ( ret != NULL )
		{
			__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
				(unsigned char *)top, (size_t) ((char *)ret-(char *)top), selected);
		}
	}
	else
	{
		/* deallocation */
		__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
			/* NOTE: OpenBSD uses "const char * end_data_segment", but we can't
			   pass "const" here, because the buffer is indeed modified. This is
			   not a problem, because the user is freeing this memory anyway. */
			(unsigned char *)end_data_segment,
			(size_t) ((char *)top-(const char *)end_data_segment), selected);
		ret = (*__lsr_real_brk_location ()) ( end_data_segment );
	}
# else /* SBRK_RETTYPE 2 <= 3 */
#  undef int
#  undef void
#  undef char
#  undef const
	/* brk() returns a pointer, but sbrk() does not return a pointer.
	  Can't get the current program break, so don't wipe anything (don't know
	  how many bytes to wipe). */
	ret = (*__lsr_real_brk_location ()) ( end_data_segment );
# endif /* SBRK_RETTYPE 2 > 3 */
#else /* BRK_RETTYPE 2 <= 3 */
	/* return type is an integral type */
# undef int
# undef void
# undef char
# undef const
	top = (*__lsr_real_sbrk_location ()) ((SBRK_ARGTYPE)0);
	/* wipe the memory first if freeing */
	if ( end_data_segment > top )
	{
		/* allocation */
		ret = (*__lsr_real_brk_location ()) ( end_data_segment );
		if ( ret == 0 )
		{
			__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
				(unsigned char *)top, (size_t) ((char *)end_data_segment-(char *)top),
				selected);
		}
	}
	else
	{
		/* deallocation */
		__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
			(unsigned char *)end_data_segment,
			(size_t) ((char *)top-(char *)end_data_segment), selected);
		ret = (*__lsr_real_brk_location ()) ( end_data_segment );
	}
#endif /* BRK_RETTYPE 2 > 3 */
	return ret;
}

/* ======================================================= */

SBRK_RETTYPE
sbrk (
#ifdef LSR_ANSIC
	SBRK_ARGTYPE increment)
#else
	increment)
	SBRK_ARGTYPE increment;
#endif
{
#ifdef HAVE_ERRNO_H
	int err = 0;
#endif
	SBRK_RETTYPE ret;
/* these defines allow checking the return type or parameter's type: */
#define const
#define int 1*
#define void 2
#define char 3
#if (SBRK_RETTYPE 2 > 3) || (SBRK_RETTYPE 2 <= 3 && BRK_RETTYPE 2 > 3)
# undef int
# undef void
# undef char
# undef const
	int selected[LSR_NPAT] = {0};
#else
# undef int
# undef void
# undef char
# undef const
#endif

/* these defines allow checking the return type or parameter's type: */
#define const
#define int 1*
#define void 2
#define char 3
#if (SBRK_RETTYPE 2 <= 3) && (BRK_RETTYPE 2 > 3)
# undef int
# undef void
# undef char
# undef const
	void * top;
#else
# undef int
# undef void
# undef char
# undef const
#endif

	__lsr_main ();
#ifdef LSR_DEBUG
	if ( __lsr_get_internal_function () == 0 )
	{
		__lsr_set_internal_function (1);
		fprintf (stderr, "libsecrm: sbrk (%d)\n", (int)increment);
		fflush (stderr);
		__lsr_set_internal_function (0);
	}
#endif

	if ( __lsr_real_sbrk_location () == NULL )
	{
#ifdef HAVE_ERRNO_H
		errno = -ENOSYS;
#endif
		return NULL;
	}
	if ( __lsr_get_internal_function () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_sbrk_location ()) ( increment );
	}

	if ( __lsr_check_prog_ban () != 0 )
	{
#ifdef HAVE_ERRNO_H
		errno = err;
#endif
		return (*__lsr_real_sbrk_location ()) ( increment );
	}

	ret = (*__lsr_real_sbrk_location ()) ( increment );
/* these defines allow checking the return type or parameter's type: */
#define const
#define int 1*
#define void 2
#define char 3
#if SBRK_RETTYPE 2 > 3
	/* return type is a pointer */
# undef int
# undef void
# undef char
# undef const
	if ( (ret != NULL) && ((int) ret != -1) )
	{
		if ( increment > 0 )
		{
			__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
				(unsigned char *)ret, (size_t) increment, selected);
		}
		else if ( increment < 0 )
		{
			__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
				(unsigned char *)ret-increment, (size_t) (-increment), selected);
		}
	}
#else /* BRK_RETTYPE 2 <= 3 */
	/* return type is an integral type. Get the current top first. */
# if BRK_RETTYPE 2 > 3
#  undef int
#  undef void
#  undef char
#  undef const
	/* return type of brk() must be a pointer to get the current top */
	if ( (__lsr_real_brk_location () != NULL) && (ret == 0) )
	{
		top = (*__lsr_real_brk_location ()) ((BRK_ARGTYPE)0);
		if ( (top != NULL) && ((int) top != -1) )
		{
			if ( increment > 0 )
			{
				__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
					(unsigned char *)top, (size_t) increment, selected);
			}
			else if ( increment < 0 )
			{
				__lsr_fill_buffer ((unsigned int) __lsr_rand () % __lsr_get_npasses (),
					(unsigned char *)top-increment, (size_t)(-increment), selected);
			}
		}
	}
# else /* BRK_RETTYPE 2 <= 3 */
	/* return type of brk() is not a pointer - we can't do anything */
#  undef int
#  undef void
#  undef char
#  undef const
# endif /* BRK_RETTYPE 2 > 3 */
#endif /* SBRK_RETTYPE 2 > 3 */
	return ret;
}
