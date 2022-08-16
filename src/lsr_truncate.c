/*
 * A library for secure removing files.
 *	-- file truncating functions' replacements.
 *
 * Copyright (C) 2007 Bogdan Drozdowski, bogdandr (at) op.pl
 * License: GNU General Public License, v2+
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
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
#include "libsecrm.h"

#ifdef HAVE_STRING_H
# if (!STDC_HEADERS) && (defined HAVE_MEMORY_H)
#  include <memory.h>
# endif
# include <string.h>
#endif

# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>	/* size_t, off_t (otherwise #define'd by ./configure) */
# endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#else
# define O_RDONLY 0
#endif

#include <stdio.h>

#ifdef HAVE_STDLIB_H
# include <stdlib.h>	/* strtoul(), random(), srandom(), rand(), srand() */
#endif


const unsigned long int npasses = PASSES;	/* Number of passes (patterns used) */

unsigned char /*@only@*/ *buf;			/* Buffer to be written to file blocks */

/* Taken from `shred' source */
static unsigned const int patterns[NPAT] =
{
	0x000, 0xFFF,					/* 1-bit */
	0x555, 0xAAA,					/* 2-bit */
	0x249, 0x492, 0x6DB, 0x924, 0xB6D, 0xDB6,	/* 3-bit */
	0x111, 0x222, 0x333, 0x444, 0x666, 0x777,
	0x888, 0x999, 0xBBB, 0xCCC, 0xDDD, 0xEEE	/* 4-bit */
};

static int selected[NPAT];

/* ======================================================= */

/**
 * Fills the given buffer with one of predefined patterns.
 * \param pat_no Pass number.
 * \param buffer Buffer to be filled.
 * \param buflen Length of the buffer.
 */
static void LSR_ATTR((nonnull))
fill_buffer ( 	unsigned long int 		pat_no,
		unsigned char* const 		buffer,
		const size_t 			buflen )
		/*@requires notnull buffer @*/ /*@sets *buffer @*/
{

	size_t i;
#if (!defined HAVE_MEMCPY) && (!defined HAVE_STRING_H)
	size_t j;
#endif
	unsigned int bits;

	if ( (buffer == NULL) || (buflen == 0) ) return;

	/* De-select all patterns once every npasses calls. */
	if ( pat_no % npasses == 0 ) {
		for ( i = 0; i < NPAT; i++ ) { selected[i] = 0; }
        }
        pat_no %= npasses;

	/* The first, last and middle passess will be using a random pattern */
	if ( (pat_no == 0) || (pat_no == npasses-1) || (pat_no == npasses/2) ) {
#if (!defined __STRICT_ANSI__) && (defined HAVE_RANDOM)
		bits = (unsigned int) (random () & 0xFFF);
#else
		bits = (unsigned int) (rand () & 0xFFF);
#endif
	} else {	/* For other passes, one of the fixed patterns is selected. */
		do {
#if (!defined __STRICT_ANSI__) && (defined HAVE_RANDOM)
			i = (size_t) (random ()%NPAT);
#else
			i = (size_t) (rand ()%NPAT);
#endif
		} while ( selected[i] == 1 );
		bits = patterns[i];
		selected[i] = 1;
    	}

	/* Taken from `shred' source and modified */
	bits |= bits << 12;
	buffer[0] = (unsigned char) ((bits >> 4) & 0xFF);
	buffer[1] = (unsigned char) ((bits >> 8) & 0xFF);
	buffer[2] = (unsigned char) (bits & 0xFF);

	for (i = 3; i < buflen / 2; i *= 2) {
#ifdef HAVE_MEMCPY
		memcpy (buffer + i, buffer, i);
#elif defined HAVE_STRING_H
		strncpy ((char *) (buffer + i), (char *)buffer, i);
#else
		for ( j=0; j<i; j++ ) {
			buffer [ i + j ] = buffer[j];
		}
#endif
	}
	if (i < buflen) {
#ifdef HAVE_MEMCPY
		memcpy (buffer + i, buffer, buflen - i);
#elif defined HAVE_STRING_H
		strncpy ((char *) (buffer + i), (char *)buffer, buflen - i);
#else
		for ( j=0; j<buflen - i; j++ ) {
			buffer [ i + j ] = buffer[j];
		}
#endif
	}
}

/* ======================================================= */

#ifndef __USE_LARGEFILE64
int
truncate (const char * const path, const off_t length)
{

# ifdef HAVE_SYS_STAT_H
	struct stat s;
# endif
	FILE *f = NULL;
	int fd = -1;
	union {
		off_t osize;
		long lsize;
	} size;
	unsigned long diff;
	unsigned int i, j;

	__lsr_main ();
# ifdef LSR_DEBUG
	printf ("libsecrm: truncate()\n");
	fflush (stdout);
# endif

	if ( __lsr_real_truncate == NULL ) {
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return -1;
	}

	if ( path == NULL ) {
		return (*__lsr_real_truncate) (path, length);
	}

	if ( strlen (path) == 0 ) {
		return (*__lsr_real_truncate) (path, length);
	}

	size.lsize = 0;

# ifdef HAVE_SYS_STAT_H
	if ( stat (path, &s) == 0 ) {
		size.osize = s.st_size;
		/* don't operate on directories */
		if ( S_ISDIR (s.st_mode) ) {
			return (*__lsr_real_truncate) (path, length);
		}
	}
#  ifdef HAVE_ERRNO_H
	else
	{
		/* file doesn't exist *
		if ( errno == ENOENT ) {*/
			return (*__lsr_real_truncate) (path, length);
		/*}*/
	}
#  endif
# else
	/* stat.h unavailable. Have to check the file size manually */
	if ( __lsr_real_fopen != NULL ) {
		f = (*__lsr_real_fopen) ( path, "r" );
		if ( f == NULL ) {
			return (*__lsr_real_truncate) (path, length);
		}
		if ( fseek ( f, 0, SEEK_END) != 0 ) {
			/* Unable to get current file length */
#  ifdef HAVE_ERRNO_H
			i  = errno;
#  endif
			fclose (f);
#  ifdef HAVE_ERRNO_H
			errno = i;
#  endif
			return (*__lsr_real_truncate) (path, length);
		}
		size.lsize = ftell (f);
		fclose (f);

	} else if ( __lsr_real_open != NULL ) {
#  ifdef HAVE_UNISTD_H	/* need close(fd) */

		fd = (*__lsr_real_open) ( path, O_RDONLY );
		if ( fd < 0 ) {
			return (*__lsr_real_truncate) (path, length);
		}
#   ifdef HAVE_ERRNO_H
		errno = 0;
#   endif
		size.lsize = lseek ( f, 0, SEEK_END);
#   ifdef HAVE_ERRNO_H
		if ( errno != 0 ) {
			i = errno;
			close (fd);
			errno = i;
			return (*__lsr_real_truncate) (path, length);
		}
#   endif
		close (fd);
#  endif
	} else {
		/* Can't get filesize */
		return (*__lsr_real_truncate) (path, length);
	}
# endif		/*  HAVE_SYS_STAT_H */
	if ( (size.osize == 0) || (length >= size.osize) ) {
		/* Nothing to do */
		return (*__lsr_real_truncate) (path, length);
	}

	if ( __lsr_real_fopen != NULL ) {

		f = (*__lsr_real_fopen) ( path, "r+" );
		if ( f == NULL ) {
			return (*__lsr_real_truncate) (path, length);
		}
		/* seeking to correct position */
		if ( fseek ( f, length+1, SEEK_SET) != 0 ) {
			/* Unable to set current file position. */
# ifdef HAVE_ERRNO_H
			i = errno;
# endif
			fclose (f);
# ifdef HAVE_ERRNO_H
			errno = i;
# endif
			return (*__lsr_real_truncate) (path, length);
		}
	} else if ( __lsr_real_open != NULL ) {
# ifdef HAVE_UNISTD_H	/* need close(fd) */

		fd = (*__lsr_real_open) ( path, O_RDWR );
		if ( fd < 0 ) {
			return (*__lsr_real_truncate) (path, length);
		}
#  ifdef HAVE_ERRNO_H
		errno = 0;
#  endif
		lseek ( fd, length+1, SEEK_SET);
#  ifdef HAVE_ERRNO_H
		if ( errno != 0 ) {
			i = errno;
			close (fd);
			errno = i;
			return (*__lsr_real_truncate) (path, length);
		}
#  endif
# endif	/* HAVE_UNISTD_H */
	} else {
		/* Can't get filesize */
		return (*__lsr_real_truncate) (path, length);
	}
	diff = size.osize - (length+1);
	if ( diff < 1024*1024 ) {
		buf = (unsigned char *) malloc ( (size_t) diff );
	}
	if ( (diff >= 1024*1024) || (buf == NULL) ) {

		buf = (unsigned char *) malloc ( (size_t) 1024 );
		if ( buf == NULL ) {
			/* Unable to get any memory. */
			if ( __lsr_real_fopen != NULL ) {
				fclose (f);
			} else {
# ifdef HAVE_UNISTD_H	/* need close(fd) */
				close (fd);
# endif
			}
			return (*__lsr_real_truncate) (path, length);
		}
		for ( j = 0; j < npasses; j++ ) {

			fill_buffer ( j, buf, (size_t) 1024 );
			for ( i = 0; i < diff/1024; i++ ) {
				if ( __lsr_real_fopen != NULL ) {
					if ( fwrite (buf, sizeof(unsigned char), 1024, f) != 1024 )
						break;
				} else {
# ifdef HAVE_UNISTD_H
					if ( write (fd, buf, 1024) != 1024 )
						break;
# endif
				}

			}
			if ( __lsr_real_fopen != NULL ) {
				if ( fwrite (buf, sizeof(unsigned char), ((unsigned) size.osize)%1024, f)
					!= ((unsigned)size.osize)%1024 ) {
						break;
				}
			} else {
# ifdef HAVE_UNISTD_H
				if ( write (fd, buf, ((unsigned) size.osize)%1024) != size.osize%1024) {
					break;
				}
# endif
			}
			/* go back to the start position of writing */
			if ( __lsr_real_fopen != NULL ) {
				if ( fseek ( f, length+1, SEEK_SET) != 0 ) {
					/* Unable to set current file position. */
# ifdef HAVE_ERRNO_H
					i = errno;
# endif
					fclose (f);
# ifdef HAVE_ERRNO_H
					errno = i;
# endif
					return (*__lsr_real_truncate) (path, length);
				}
			} else {
# ifdef HAVE_UNISTD_H
				if ( lseek ( fd, length+1, SEEK_SET) < 0 ) {
					/* Unable to set current file position. */
#  ifdef HAVE_ERRNO_H
					i = errno;
#  endif
					close (fd);
#  ifdef HAVE_ERRNO_H
					errno = i;
#  endif
					return (*__lsr_real_truncate) (path, length);
				}
# endif
			}
		}
		free (buf);

	} else if ( buf != NULL ) {

		for ( j = 0; j < npasses; j++ ) {

			fill_buffer ( j, buf, (size_t)diff );
			if ( __lsr_real_fopen != NULL ) {
				if ( fwrite (buf, sizeof(unsigned char), diff, f) != diff )
					break;
			} else {
# ifdef HAVE_UNISTD_H
				if ( write (fd, buf, diff) != (ssize_t)diff) {
					break;
				}
# endif
			}

			/* go back to the start position of writing */
			if ( __lsr_real_fopen != NULL ) {
				if ( fseek ( f, length+1, SEEK_SET) != 0 ) {
					/* Unable to set current file position. */
# ifdef HAVE_ERRNO_H
					i = errno;
# endif
					fclose (f);
# ifdef HAVE_ERRNO_H
					errno = i;
# endif
					return (*__lsr_real_truncate) (path, length);
				}
			} else {
# ifdef HAVE_UNISTD_H
				if ( lseek ( fd, length+1, SEEK_SET) < 0 ) {
					/* Unable to set current file position. */
#  ifdef HAVE_ERRNO_H
					i = errno;
#  endif
					close (fd);
#  ifdef HAVE_ERRNO_H
					errno = i;
#  endif
					return (*__lsr_real_truncate) (path, length);
				}
# endif
			}
		}
		free (buf);
	}

	return (*__lsr_real_truncate) (path, length);
}
#else /* __USE_LARGEFILE64 */
/* ======================================================= */

int
truncate64 (const char * const path, const __off64_t length)
{

# ifdef HAVE_SYS_STAT_H
	struct stat64 s;
# endif
	FILE *f = NULL;
	int fd = -1;
	union {
		__off64_t osize;
		long long lsize;
	} size;
	unsigned long long diff;
	unsigned long long int i;
	unsigned int j;

	__lsr_main ();
# ifdef LSR_DEBUG
	printf ("libsecrm: truncate64()\n");
	fflush (stdout);
# endif

	if ( __lsr_real_truncate64 == NULL ) {
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return -1;
	}

	if ( path == NULL ) {
		return (*__lsr_real_truncate64) (path, length);
	}

	if ( strlen (path) == 0 ) {
		return (*__lsr_real_truncate64) (path, length);
	}

	size.lsize = 0;

# ifdef HAVE_SYS_STAT_H
	if ( stat64 (path, &s) == 0 ) {
		size.osize = s.st_size;
		/* don't operate on directories */
		if ( S_ISDIR (s.st_mode) ) {
			return (*__lsr_real_truncate64) (path, length);
		}
	}
#  ifdef HAVE_ERRNO_H
	else
	{
		/* file doesn't exist *
		if ( errno == ENOENT ) {*/
			return (*__lsr_real_truncate64) (path, length);
		/*}*/
	}
#  endif
# else
	/* stat.h unavailable. Have to check the file size manually */
	if ( __lsr_real_fopen64 != NULL ) {
		f = (*__lsr_real_fopen64) ( path, "r" );
		if ( f == NULL ) {
			return (*__lsr_real_truncate64) (path, length);
		}
		if ( fseek ( f, 0, SEEK_END) != 0 ) {
			/* Unable to get current file length */
#  ifdef HAVE_ERRNO_H
			i  = errno;
#  endif
			fclose (f);
#  ifdef HAVE_ERRNO_H
			errno = i;
#  endif
			return (*__lsr_real_truncate64) (path, length);
		}
		size.lsize = ftell64 (f);
		fclose (f);

	} else if ( __lsr_real_open64 != NULL ) {
# ifdef HAVE_UNISTD_H	/* need close(fd) */

		fd = (*__lsr_real_open64) ( path, O_RDONLY );
		if ( fd < 0 ) {
			return (*__lsr_real_truncate64) (path, length);
		}
#  ifdef HAVE_ERRNO_H
		errno = 0;
#  endif
		size.lsize = lseek64 ( f, 0, SEEK_END);
#  ifdef HAVE_ERRNO_H
		if ( errno != 0 ) {
			i = errno;
			close (fd);
			errno = i;
			return (*__lsr_real_truncate64) (path, length);
		}
#  endif
		close (fd);
# endif
	} else {
		/* Can't get filesize */
		return (*__lsr_real_truncate64) (path, length);
	}
# endif
	if ( (size.osize == 0) || (length >= size.osize) ) {
		/* Nothing to do */
		return (*__lsr_real_truncate64) (path, length);
	}

	if ( __lsr_real_fopen64 != NULL ) {

		f = (*__lsr_real_fopen64) ( path, "r+" );
		if ( f == NULL ) {
			return (*__lsr_real_truncate64) (path, length);
		}
		/* seeking to correct position */
		if ( fseek ( f, (long)length+1, SEEK_SET) != 0 ) {
			/* Unable to set current file position. */
# ifdef HAVE_ERRNO_H
			i = errno;
# endif
			fclose (f);
# ifdef HAVE_ERRNO_H
			errno = i;
# endif
			return (*__lsr_real_truncate64) (path, length);
		}
	} else if ( __lsr_real_open64 != NULL ) {
# ifdef HAVE_UNISTD_H	/* need close(fd) */

		fd = (*__lsr_real_open64) ( path, O_RDWR );
		if ( fd < 0 ) {
			return (*__lsr_real_truncate64) (path, length);
		}
#  ifdef HAVE_ERRNO_H
		errno = 0;
#  endif
		lseek64 ( fd, length+1, SEEK_SET);
#  ifdef HAVE_ERRNO_H
		if ( errno != 0 ) {
			i = errno;
			close (fd);
			errno = i;
			return (*__lsr_real_truncate64) (path, length);
		}
#  endif
# endif	/* HAVE_UNISTD_H */
	} else {
		/* Can't get filesize */
		return (*__lsr_real_truncate64) (path, length);
	}
	diff = size.osize - (length+1);
	if ( diff < 1024*1024 ) {
		buf = (unsigned char *) malloc ( (size_t) diff );
	}
	if ( (diff >= 1024*1024) || (buf == NULL) ) {

		buf = (unsigned char *) malloc ( (size_t) 1024 );
		if ( buf == NULL ) {
			/* Unable to get any memory. */
			if ( __lsr_real_fopen64 != NULL ) {
				fclose (f);
			} else {
# ifdef HAVE_UNISTD_H	/* need close(fd) */
				close (fd);
# endif
			}
			return (*__lsr_real_truncate64) (path, length);
		}
		for ( j = 0; j < npasses; j++ ) {

			fill_buffer ( j, buf, (size_t) 1024 );
			for ( i = 0; i < diff/1024; i++ ) {
				if ( __lsr_real_fopen64 != NULL ) {
					if ( fwrite (buf, sizeof(unsigned char), 1024, f) != 1024 )
						break;
				} else {
# ifdef HAVE_UNISTD_H
					if ( write (fd, buf, 1024) != 1024 )
						break;
# endif
				}

			}
			if ( __lsr_real_fopen64 != NULL ) {
				if ( fwrite (buf, sizeof(unsigned char), ((unsigned) size.osize)%1024, f)
					!= ((unsigned)size.osize)%1024 ) {
						break;
				}
			} else {
# ifdef HAVE_UNISTD_H
				if ( write (fd, buf, ((unsigned) size.osize)%1024) != size.osize%1024) {
					break;
				}
# endif
			}
			/* go back to the start position of writing */
			if ( __lsr_real_fopen64 != NULL ) {
				if ( fseek ( f, (long)length+1, SEEK_SET) != 0 ) {
					/* Unable to set current file position. */
# ifdef HAVE_ERRNO_H
					i = errno;
# endif
					fclose (f);
# ifdef HAVE_ERRNO_H
					errno = i;
# endif
					return (*__lsr_real_truncate64) (path, length);
				}
			} else {
# ifdef HAVE_UNISTD_H
				if ( lseek64 ( fd, length+1, SEEK_SET) < 0 ) {
					/* Unable to set current file position. */
#  ifdef HAVE_ERRNO_H
					i = errno;
#  endif
					close (fd);
#  ifdef HAVE_ERRNO_H
					errno = i;
#  endif
					return (*__lsr_real_truncate64) (path, length);
				}
# endif
			}
		}
		free (buf);

	} else if ( buf != NULL ) {	/* diff < 1024^2 */

		for ( j = 0; j < npasses; j++ ) {

			fill_buffer ( j, buf, (size_t)diff );
			if ( __lsr_real_fopen64 != NULL ) {
				if ( fwrite (buf, sizeof(unsigned char), (size_t)diff, f) != diff )
					break;
			} else {
# ifdef HAVE_UNISTD_H
				if ( write (fd, buf, (size_t)diff) != (ssize_t)diff) {
					break;
				}
# endif
			}

			/* go back to the start position of writing */
			if ( __lsr_real_fopen64 != NULL ) {
				if ( fseek ( f, (long)length+1, SEEK_SET) != 0 ) {
					/* Unable to set current file position. */
# ifdef HAVE_ERRNO_H
					i = errno;
# endif
					fclose (f);
# ifdef HAVE_ERRNO_H
					errno = i;
# endif
					return (*__lsr_real_truncate64) (path, length);
				}
			} else {
# ifdef HAVE_UNISTD_H
				if ( lseek64 ( fd, length+1, SEEK_SET) < 0 ) {
					/* Unable to set current file position. */
#  ifdef HAVE_ERRNO_H
					i = errno;
#  endif
					close (fd);
#  ifdef HAVE_ERRNO_H
					errno = i;
#  endif
					return (*__lsr_real_truncate64) (path, length);
				}
# endif
			}
		}
		free (buf);
	}

	return (*__lsr_real_truncate64) (path, length);
}
#endif	/* __USE_LARGEFILE64 */

/* ======================================================= */

#ifndef __USE_LARGEFILE64
int
ftruncate ( int fd, const off_t length)
{

# ifdef HAVE_SYS_STAT_H
	struct stat s;
# endif
	off_t size = 0;
# ifdef HAVE_UNISTD_H
	off_t pos;
# endif
	unsigned long diff;
	unsigned int i, j;

	__lsr_main ();
# ifdef LSR_DEBUG
	printf ("libsecrm: ftruncate()\n");
	fflush (stdout);
# endif

	if ( __lsr_real_ftruncate == NULL ) {
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return -1;
	}

# ifdef HAVE_SYS_STAT_H
	if ( fstat (fd, &s) == 0 ) {
		size = s.st_size;
		/* don't operate on directories */
		if ( S_ISDIR (s.st_mode) ) {
			return (*__lsr_real_ftruncate) (fd, length);
		}
	}
#  ifdef HAVE_ERRNO_H
	else
	{
		/* file doesn't exist *
		if ( errno == ENOENT ) {*/
			return (*__lsr_real_ftruncate) (fd, length);
		/*}*/
	}
#  endif

# else	/* No sys/stat.h */

#  ifdef HAVE_UNISTD_H
	size = lseek ( fd, 0, SEEK_END );
#  else
	/* Can't get current file size */
	return (*__lsr_real_ftruncate) (fd, length);
#  endif

# endif	/* sys/stat.h */

# ifdef HAVE_UNISTD_H
	pos = lseek ( fd, 0, SEEK_CUR );
# else
	/* Can't get current file offset */
	return (*__lsr_real_ftruncate) (fd, length);
# endif
	if ( (size == 0) || (length >= size) ) {
		/* Nothing to do */
		return (*__lsr_real_ftruncate) (fd, length);
	}
	/* seeking to correct position */
	if ( lseek ( fd, length+1, SEEK_SET) != length+1 ) {
		/* Unable to set current file position. */
		return (*__lsr_real_ftruncate) (fd, length);
	}

	diff = size - (length+1);
	if ( diff < 1024*1024 ) {
		buf = (unsigned char *) malloc ( (size_t) diff );
	}
	if ( (diff >= 1024*1024) || (buf == NULL) ) {

		buf = (unsigned char *) malloc ( (size_t) 1024 );
		if ( buf == NULL ) {
			/* Unable to get any memory. */
			return (*__lsr_real_ftruncate) (fd, length);
		}
		for ( j = 0; j < npasses; j++ ) {

			fill_buffer ( j, buf, (size_t) 1024 );
			for ( i = 0; i < diff/1024; i++ ) {
				if ( write (fd, buf, 1024) != 1024 )
					break;
			}
			if ( write (fd, buf, ((unsigned) size)%1024) != ((ssize_t) size)%1024 )
				break;
			/* go back to the start position of writing */
			if ( lseek ( fd, length+1, SEEK_SET) != length+1 ) {
				/* Unable to set current file position. */
				return (*__lsr_real_ftruncate) (fd, length);
			}
		}
		free(buf);

	} else if ( buf != NULL ) {

		for ( j = 0; j < npasses; j++ ) {

			fill_buffer ( j, buf, (size_t)diff );
			if ( write (fd, buf, diff) != (ssize_t) diff )
				break;

			/* go back to the start position of writing */
			if ( lseek ( fd, length+1, SEEK_SET) != length+1 ) {
				/* Unable to set current file position. */
				return (*__lsr_real_ftruncate) (fd, length);
			}
		}
		free (buf);
	}

	lseek ( fd, pos, SEEK_SET );

	return (*__lsr_real_ftruncate) (fd, length);
}
#else /* __USE_LARGEFILE64 */
/* ======================================================= */

int
ftruncate64 ( int fd, const __off64_t length)
{

# ifdef HAVE_SYS_STAT_H
	struct stat64 s;
# endif
	__off64_t size = 0;
# ifdef HAVE_UNISTD_H
	__off64_t pos;
# endif
	unsigned long long diff;
	unsigned long long int i;
	unsigned int j;

	__lsr_main ();
# ifdef LSR_DEBUG
	printf ("libsecrm: ftruncate64()\n");
	fflush (stdout);
# endif

	if ( __lsr_real_ftruncate64 == NULL ) {
# ifdef HAVE_ERRNO_H
		errno = ENOSYS;
# endif
		return -1;
	}

# ifdef HAVE_SYS_STAT_H
	if ( fstat64 (fd, &s) == 0 ) {
		size = s.st_size;
		/* don't operate on directories */
		if ( S_ISDIR (s.st_mode) ) {
			return (*__lsr_real_ftruncate64) (fd, length);
		}
	}
#  ifdef HAVE_ERRNO_H
	else
	{
		/* file doesn't exist *
		if ( errno == ENOENT ) {*/
			return (*__lsr_real_ftruncate64) (fd, length);
		/*}*/
	}
#  endif

# else	/* No sys/stat.h */

#  ifdef HAVE_UNISTD_H
	size = lseek64 ( fd, 0, SEEK_END );
#  else
	/* Can't get current file size */
	return (*__lsr_real_ftruncate64) (fd, length);
#  endif

# endif	/* sys/stat.h */

# ifdef HAVE_UNISTD_H
	pos = lseek64 ( fd, (off64_t)0, SEEK_CUR );
# else
	/* Can't get current file offset */
	return (*__lsr_real_ftruncate64) (fd, length);
# endif
	if ( (size == 0) || (length >= size) ) {
		/* Nothing to do */
		return (*__lsr_real_ftruncate64) (fd, length);
	}
	/* seeking to correct position */
	if ( lseek64 ( fd, length+1, SEEK_SET) != length+1 ) {
		/* Unable to set current file position. */
		return (*__lsr_real_ftruncate64) (fd, length);
	}

	diff = size - (length+1);
	if ( diff < 1024*1024 ) {
		buf = (unsigned char *) malloc ( (size_t) diff );
	}
	if ( (diff >= 1024*1024) || (buf == NULL) ) {

		buf = (unsigned char *) malloc ( (size_t) 1024 );
		if ( buf == NULL ) {
			/* Unable to get any memory. */
			return (*__lsr_real_ftruncate64) (fd, length);
		}
		for ( j = 0; j < npasses; j++ ) {

			fill_buffer ( j, buf, (size_t) 1024 );
			for ( i = 0; i < diff/1024; i++ ) {
				if ( write (fd, buf, 1024) != 1024 )
					break;
			}
			if ( write (fd, buf, ((unsigned) size)%1024) != ((ssize_t) size)%1024 )
				break;
			/* go back to the start position of writing */
			if ( lseek64 ( fd, length+1, SEEK_SET) != length+1 ) {
				/* Unable to set current file position. */
				return (*__lsr_real_ftruncate64) (fd, length);
			}
		}
		free(buf);

	} else if ( buf != NULL ) {	/* diff < 1024^2 */

		for ( j = 0; j < npasses; j++ ) {

			fill_buffer ( j, buf, (size_t)diff );
			if ( write (fd, buf, (size_t)diff) != (ssize_t) diff )
				break;

			/* go back to the start position of writing */
			if ( lseek64 ( fd, length+1, SEEK_SET) != length+1 ) {
				/* Unable to set current file position. */
				return (*__lsr_real_ftruncate64) (fd, length);
			}
		}
		free (buf);
	}

	lseek64 ( fd, pos, SEEK_SET );

	return (*__lsr_real_ftruncate64) (fd, length);
}
#endif /* __USE_LARGEFILE64 */
