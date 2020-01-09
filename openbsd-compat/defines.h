/*
 * Copyright (c) 2016 Gilles Chehade <gilles@poolp.org>.  All rights reserved.
 * Copyright (c) 1999-2003 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _DEFINES_H
#define _DEFINES_H

/* $Id: defines.h,v 1.181 2014/06/11 19:22:50 dtucker Exp $ */


/* Constants */
#ifndef EAUTH
# define EAUTH 80
#endif

#ifndef HOST_NAME_MAX
# ifdef _POSIX_HOST_NAME_MAX
# define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
# endif
#endif

#ifndef PATH_MAX
# ifdef _POSIX_PATH_MAX
# define PATH_MAX _POSIX_PATH_MAX
# endif
#endif

#ifndef MAXPATHLEN
# ifdef PATH_MAX
#  define MAXPATHLEN PATH_MAX
# else /* PATH_MAX */
#  define MAXPATHLEN 64
#  define PATH_MAX 64
/* realpath uses a fixed buffer of size MAXPATHLEN, so force use of ours */
#  ifndef BROKEN_REALPATH
#   define BROKEN_REALPATH 1
#  endif /* BROKEN_REALPATH */
# endif /* PATH_MAX */
#endif /* MAXPATHLEN */

#ifndef MAXHOSTNAMELEN
# define MAXHOSTNAMELEN  64
#endif

#ifndef LOGIN_NAME_MAX
# define LOGIN_NAME_MAX 32
#endif

#ifndef MAXLOGNAME
#define MAXLOGNAME      LOGIN_NAME_MAX
#endif

#ifndef UID_MAX
#define	UID_MAX	UINT_MAX
#endif
#ifndef GID_MAX
#define	GID_MAX	UINT_MAX
#endif

#ifndef STDIN_FILENO
# define STDIN_FILENO    0
#endif
#ifndef STDOUT_FILENO
# define STDOUT_FILENO   1
#endif
#ifndef STDERR_FILENO
# define STDERR_FILENO   2
#endif

#if !HAVE_DECL_O_NONBLOCK
# define O_NONBLOCK      00004	/* Non Blocking Open */
#endif

#ifndef S_ISDIR
# define S_ISDIR(mode)	(((mode) & (_S_IFMT)) == (_S_IFDIR))
#endif /* S_ISDIR */

#ifndef S_ISREG
# define S_ISREG(mode)	(((mode) & (_S_IFMT)) == (_S_IFREG))
#endif /* S_ISREG */

#ifndef S_ISLNK
# define S_ISLNK(mode)	(((mode) & S_IFMT) == S_IFLNK)
#endif /* S_ISLNK */

#ifndef S_IXUSR
# define S_ISUID			0004000	/* set-uid */
# define S_ISGID			0002000	/* set-gid */
# define S_ISVTX			0001000	/* sticky */
# define S_IXUSR			0000100	/* execute/search permission, */
# define S_IXGRP			0000010	/* execute/search permission, */
# define S_IXOTH			0000001	/* execute/search permission, */
# define _S_IWUSR			0000200	/* write permission, */
# define S_IWUSR			_S_IWUSR	/* write permission, owner */
# define S_IWGRP			0000020	/* write permission, group */
# define S_IWOTH			0000002	/* write permission, other */
# define S_IRUSR			0000400	/* read permission, owner */
# define S_IRGRP			0000040	/* read permission, group */
# define S_IROTH			0000004	/* read permission, other */
# define S_IRWXU			0000700	/* read, write, execute */
# define S_IRWXG			0000070	/* read, write, execute */
# define S_IRWXO			0000007	/* read, write, execute */
#endif /* S_IXUSR */

#if !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
#define MAP_ANON MAP_ANONYMOUS
#endif

#ifndef MAP_FAILED
# define MAP_FAILED ((void *)-1)
#endif

/*
SCO Open Server 3 has INADDR_LOOPBACK defined in rpc/rpc.h but
including rpc/rpc.h breaks Solaris 6
*/
#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK ((u_long)0x7f000001)
#endif


/* Types */
#ifndef HAVE_U_CHAR
typedef unsigned char u_char;
# define HAVE_U_CHAR
#endif /* HAVE_U_CHAR */

#ifndef HAVE_U_INT
typedef unsigned int u_int;
# define HAVE_U_INT
#endif

#ifndef HAVE_INTMAX_T
typedef long long intmax_t;
# define HAVE_INTMAX_T
#endif

#ifndef HAVE_UINTMAX_T
typedef unsigned long long uintmax_t;
# define HAVE_UINTMAX_T
#endif

#ifndef HAVE_SA_FAMILY_T
typedef int sa_family_t;
# define HAVE_SA_FAMILY_T
#endif /* HAVE_SA_FAMILY_T */

#ifndef HAVE_SIG_ATOMIC_T
typedef int sig_atomic_t;
# define HAVE_SIG_ATOMIC_T
#endif /* HAVE_SIG_ATOMIC_T */


#ifndef ULLONG_MAX
# define ULLONG_MAX ((unsigned long long)-1)
#endif

#ifndef SIZE_T_MAX
#define SIZE_T_MAX ULONG_MAX
#endif /* SIZE_T_MAX */

#ifndef SIZE_MAX
#define SIZE_MAX SIZE_T_MAX
#endif



#if !defined(HAVE_SS_FAMILY_IN_SS) && defined(HAVE___SS_FAMILY_IN_SS)
# define ss_family __ss_family
#endif /* !defined(HAVE_SS_FAMILY_IN_SS) && defined(HAVE_SA_FAMILY_IN_SS) */

#ifndef HAVE_SYS_UN_H
struct	sockaddr_un {
	short	sun_family;		/* AF_UNIX */
	char	sun_path[108];		/* path name (gag) */
};
#endif /* HAVE_SYS_UN_H */

#ifndef HAVE_IN_ADDR_T
typedef uint32_t	in_addr_t;
#endif

#ifndef HAVE_IN_PORT_T
typedef uint16_t	in_port_t;
#endif


/* Paths */

/* needed by compat/daemon.c */
#ifndef _PATH_DEVNULL
# define _PATH_DEVNULL "/dev/null"
#endif

/* user may have set a different path */
#if defined(_PATH_MAILDIR) && defined(MAIL_DIRECTORY)
# undef _PATH_MAILDIR
#endif /* defined(_PATH_MAILDIR) && defined(MAIL_DIRECTORY) */

#ifdef MAIL_DIRECTORY
# define _PATH_MAILDIR MAIL_DIRECTORY
#endif

#ifdef MAILDIR
# undef MAILDIR
#endif



/* Macros */

/* needed by compat */
#ifndef MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
#endif
#ifndef MIN
# define MIN(a,b) (((a)<(b))?(a):(b))
#endif

/* needed by smtpd */
#ifndef timespeccmp
#define timespeccmp(a, b, cmp)			       		\
	(((a)->tv_sec == (b)->tv_sec) ?			       	\
	 ((a)->tv_nsec cmp (b)->tv_nsec) :	       		\
	 ((a)->tv_sec cmp (b)->tv_sec))
#endif

/* needed by smtpd */
#ifndef timespecsub
#define timespecsub(a, b, result)				\
   do {								\
      (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;		\
      (result)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec;		\
      if ((result)->tv_nsec < 0) {				\
	 --(result)->tv_sec;					\
	 (result)->tv_nsec += 1000000000L;			\
      }								\
   } while (0)
#endif

/* needed by smtpd */
#ifndef TIMEVAL_TO_TIMESPEC
#define	TIMEVAL_TO_TIMESPEC(tv, ts) {					\
	(ts)->tv_sec = (tv)->tv_sec;					\
	(ts)->tv_nsec = (tv)->tv_usec * 1000;				\
}
#endif

/* needed by compat */
#ifndef TIMESPEC_TO_TIMEVAL
#define	TIMESPEC_TO_TIMEVAL(tv, ts) {					\
	(tv)->tv_sec = (ts)->tv_sec;					\
	(tv)->tv_usec = (ts)->tv_nsec / 1000;				\
}
#endif

#ifndef __P
# define __P(x) x
#endif

#if !defined(IN6_IS_ADDR_V4MAPPED)
# define IN6_IS_ADDR_V4MAPPED(a) \
	((((uint32_t *) (a))[0] == 0) && (((uint32_t *) (a))[1] == 0) && \
	 (((uint32_t *) (a))[2] == htonl (0xffff)))
#endif /* !defined(IN6_IS_ADDR_V4MAPPED) */

#if !defined(__GNUC__) || (__GNUC__ < 2)
# define __attribute__(x)
#endif /* !defined(__GNUC__) || (__GNUC__ < 2) */

#ifndef __dead
# define __dead	__attribute__((noreturn))
#endif

#if !defined(HAVE_ATTRIBUTE__SENTINEL__) && !defined(__sentinel__)
# define __sentinel__
#endif

#if !defined(HAVE_ATTRIBUTE__BOUNDED__) && !defined(__bounded__)
# define __bounded__(x, y, z)
#endif

#if !defined(HAVE_ATTRIBUTE__NONNULL__) && !defined(__nonnull__)
# define __nonnull__(x)
#endif

#ifndef OSSH_ALIGNBYTES
#define OSSH_ALIGNBYTES	(sizeof(int) - 1)
#endif
#ifndef __CMSG_ALIGN
#define	__CMSG_ALIGN(p) (((u_int)(p) + OSSH_ALIGNBYTES) &~ OSSH_ALIGNBYTES)
#endif

/* Length of the contents of a control message of length len */
#ifndef CMSG_LEN
#define	CMSG_LEN(len)	(__CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
#endif

/* Length of the space taken up by a padded control message of length len */
#ifndef CMSG_SPACE
#define	CMSG_SPACE(len)	(__CMSG_ALIGN(sizeof(struct cmsghdr)) + __CMSG_ALIGN(len))
#endif

/* given pointer to struct cmsghdr, return pointer to data */
#ifndef CMSG_DATA
#define CMSG_DATA(cmsg) ((u_char *)(cmsg) + __CMSG_ALIGN(sizeof(struct cmsghdr)))
#endif /* CMSG_DATA */

/*
 * RFC 2292 requires to check msg_controllen, in case that the kernel returns
 * an empty list for some reasons.
 */
#ifndef CMSG_FIRSTHDR
#define CMSG_FIRSTHDR(mhdr) \
	((mhdr)->msg_controllen >= sizeof(struct cmsghdr) ? \
	 (struct cmsghdr *)(mhdr)->msg_control : \
	 (struct cmsghdr *)NULL)
#endif /* CMSG_FIRSTHDR */


/* Set up BSD-style BYTE_ORDER definition if it isn't there already */
/* XXX: doesn't try to cope with strange byte orders (PDP_ENDIAN) */
#ifndef BYTE_ORDER
# ifndef LITTLE_ENDIAN
#  define LITTLE_ENDIAN  1234
# endif /* LITTLE_ENDIAN */
# ifndef BIG_ENDIAN
#  define BIG_ENDIAN     4321
# endif /* BIG_ENDIAN */
# ifdef WORDS_BIGENDIAN
#  define BYTE_ORDER BIG_ENDIAN
# else /* WORDS_BIGENDIAN */
#  define BYTE_ORDER LITTLE_ENDIAN
# endif /* WORDS_BIGENDIAN */
#endif /* BYTE_ORDER */

/* Function replacement / compatibility hacks */

#if defined(BROKEN_GETADDRINFO) && defined(HAVE_GETADDRINFO)
# undef HAVE_GETADDRINFO
#endif
#if defined(BROKEN_GETADDRINFO) && defined(HAVE_FREEADDRINFO)
# undef HAVE_FREEADDRINFO
#endif
#if defined(BROKEN_GETADDRINFO) && defined(HAVE_GAI_STRERROR)
# undef HAVE_GAI_STRERROR
#endif

#if !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY)
# define memmove(s1, s2, n) bcopy((s2), (s1), (n))
#endif /* !defined(HAVE_MEMMOVE) && defined(HAVE_BCOPY) */

#if !defined(HAVE___func__) && defined(HAVE___FUNCTION__)
#  define __func__ __FUNCTION__
#elif !defined(HAVE___func__)
#  define __func__ ""
#endif


/* Maximum number of file descriptors available */
/* needed by compat/bsd-closefrom.c */
#ifndef OPEN_MAX
# ifdef HAVE_SYSCONF
#  define OPEN_MAX	sysconf(_SC_OPEN_MAX)
# else
#  define OPEN_MAX	256
# endif
#endif



/** end of login recorder definitions */

#ifndef IOV_MAX
# if defined(_XOPEN_IOV_MAX)
#  define	IOV_MAX		_XOPEN_IOV_MAX
# elif defined(DEF_IOV_MAX)
#  define	IOV_MAX		DEF_IOV_MAX
# else
#  define	IOV_MAX		16
# endif
#endif

#ifndef EWOULDBLOCK
# define EWOULDBLOCK EAGAIN
#endif

#ifndef INET6_ADDRSTRLEN	/* for non IPv6 machines */
#define INET6_ADDRSTRLEN 46
#endif

#ifndef HAVE_VA_COPY
# ifdef HAVE___VA_COPY
#  define va_copy(dest, src) __va_copy(dest, src)
# else
#  define va_copy(dest, src) (dest) = (src)
# endif
#endif

/* OpenSMTPD-portable specific entries */

/* From OpenNTPD portable */
#if !defined(SA_LEN)
# if defined(HAVE_STRUCT_SOCKADDR_SA_LEN)
#  define SA_LEN(x)	((x)->sa_len)
# else
#  define SA_LEN(x)     ((x)->sa_family == AF_INET6 ? \
			sizeof(struct sockaddr_in6) : \
			sizeof(struct sockaddr_in))
# endif
#endif

/* From OpenBGPD portable */
#if !defined(SS_LEN)
# if defined(HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN)
#  define SS_LEN(x)  ((x)->ss_len)
# else
#  define SS_LEN(x)  SA_LEN((struct sockaddr *)(x))
# endif
#endif

#ifdef HAVE_SS_LEN
# define STORAGE_LEN(X) ((X).ss_len)
# define SET_STORAGE_LEN(X, Y) do { STORAGE_LEN(X) = (Y); } while(0)
#elif defined(HAVE___SS_LEN)
# define STORAGE_LEN(X) ((X).__ss_len)
# define SET_STORAGE_LEN(X, Y) do { STORAGE_LEN(X) = (Y); } while(0)
#else
# define STORAGE_LEN(X) (STORAGE_FAMILY(X) == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))
# define SET_STORAGE_LEN(X, Y) (void) 0
#endif

/* chl parts */
#ifndef EAI_NODATA
# ifdef EAI_NONAME
#  define EAI_NODATA EAI_NONAME
# else
#  error "Neither EAI_NODATA and EAI_NONAME are defined! :("
# endif
#endif
/* end of chl */

#ifndef HAVE_FPARSELN
/*
 * fparseln() specific operation flags.
 */
#define FPARSELN_UNESCESC       0x01
#define FPARSELN_UNESCCONT      0x02
#define FPARSELN_UNESCCOMM      0x04
#define FPARSELN_UNESCREST      0x08
#define FPARSELN_UNESCALL       0x0f
#endif

#ifdef HAVE_M_DATA
#undef M_DATA
#endif

#ifndef SCOPE_DELIMITER
#define	SCOPE_DELIMITER '%'
#endif

#ifndef HAVE_FLOCK
#define LOCK_SH         0x01            /* shared file lock */
#define LOCK_EX         0x02            /* exclusive file lock */
#define LOCK_NB         0x04            /* don't block when locking */
#define LOCK_UN         0x08            /* unlock file */
#endif

#if !HAVE_DECL_LOG_PERROR
#define LOG_PERROR 0
#endif

#ifndef MAXDNAME
#define MAXDNAME 1025
#endif

#endif /* _DEFINES_H */
