/* $Id: openbsd-compat.h,v 1.51 2010/10/07 10:25:29 djm Exp $ */

/*
 * Copyright (c) 1999-2003 Damien Miller.  All rights reserved.
 * Copyright (c) 2003 Ben Lindstrom. All rights reserved.
 * Copyright (c) 2002 Tim Rice.  All rights reserved.
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

#ifndef _OPENBSD_COMPAT_H
#define _OPENBSD_COMPAT_H

#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>

/* OpenBSD function replacements */
#include "base64.h"

#include <sys/queue.h>
#include <sys/tree.h>
#include "bsd-vis.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifndef HAVE_BASENAME
char *basename(const char *path);
#endif

#ifndef HAVE_CLOSEFROM
void closefrom(int);
#endif

#if !defined(HAVE_REALPATH) || defined(BROKEN_REALPATH)
char *realpath(const char *path, char *resolved);
#endif 

#if !HAVE_DECL_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t size);
#endif

#if !HAVE_DECL_STRLCAT
size_t strlcat(char *dst, const char *src, size_t size);
#endif

#ifndef HAVE_STRMODE
void strmode(int mode, char *p);
#endif

#ifndef HAVE_DAEMON
int daemon(int nochdir, int noclose);
#endif 

#ifndef HAVE_DIRNAME
char *dirname(const char *path);
#endif

#ifndef HAVE_FMT_SCALED
#define	FMT_SCALED_STRSIZE	7
int	fmt_scaled(long long number, char *result);
#endif

#ifndef HAVE_SCAN_SCALED
int	scan_scaled(char *, long long *);
#endif

#ifndef HAVE_RES_RANDOMID
unsigned int res_randomid(void);
#endif

#ifndef HAVE_STRSEP
char *strsep(char **stringp, const char *delim);
#endif

#ifndef HAVE_SETPROCTITLE
void setproctitle(const char *fmt, ...);
void compat_init_setproctitle(int argc, char *argv[]);
#endif

#ifndef HAVE_GETDTABLECOUNT
int getdtablecount(void);
#endif

#ifndef HAVE_GETDTABLESIZE
int getdtablesize(void);
#endif

#if !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
int BSDgetopt(int argc, char * const *argv, const char *opts);
#endif

/* Home grown routines */
/* #include "bsd-setres_id.h" */
/* #include "bsd-statvfs.h" */
#include "waitpid.h"
/* #include "bsd-poll.h" */

#ifndef HAVE_GETPEEREID
int getpeereid(int , uid_t *, gid_t *);
#endif 

#if !defined(HAVE_ARC4RANDOM) || defined(LIBRESSL_VERSION_NUMBER)
unsigned int arc4random(void);
#endif

#if 0
#if defined(LIBRESSL_VERSION_NUMBER)
# define arc4random_stir()
#elif defined(HAVE_ARC4RANDOM_STIR)
void arc4random_stir(void);
#elif defined(HAVE_ARC4RANDOM)
/* Recent system/libressl implementation; no need for explicit stir */
# define arc4random_stir()
#else
/* openbsd-compat/arc4random.c provides arc4random_stir() */
void arc4random_stir(void);
#endif
#endif

#if !defined(HAVE_ARC4RANDOM_BUF) || defined(LIBRESSL_VERSION_NUMBER)
void arc4random_buf(void *, size_t);
#endif

#if !defined(HAVE_ARC4RANDOM_UNIFORM) || defined(LIBRESSL_VERSION_NUMBER)
uint32_t arc4random_uniform(uint32_t);
#endif

#if !defined(SSL_OP_NO_CLIENT_RENEGOTIATION) && !defined(LIBRESSL_VERSION_NUMBER)
#define SSL_OP_NO_CLIENT_RENEGOTIATION 0
#endif

/* #include <sys/types.h> XXX needed? For size_t */

#ifndef HAVE_STRTOLL
long long strtoll(const char *, char **, int);
#endif

#ifndef HAVE_STRTOUL
unsigned long strtoul(const char *, char **, int);
#endif

#ifndef HAVE_STRTOULL
unsigned long long strtoull(const char *, char **, int);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(const char *nptr, long long minval, long long maxval, const char **errstr);
#endif

#if !defined(HAVE_EXPLICIT_BZERO) || defined(LIBRESSL_VERSION_NUMBER)
void explicit_bzero(void *p, size_t n);
#endif

/* OpenSMTPD-portable specific entries */

#ifndef HAVE_FGETLN
#include <stdio.h>
#include <string.h>
char * fgetln(FILE *stream, size_t *len);
#endif

#ifndef HAVE_FPARSELN
#include <stdio.h>
#include <string.h>
char * fparseln(FILE *fp, size_t *size, size_t *lineno, const char str[3], int flags);
#endif

#ifndef HAVE_FREEZERO
void freezero(void *, size_t);
#endif

#ifndef HAVE_PIDFILE
int pidfile(const char *basename);
#endif

#if !defined(HAVE_REALLOCARRAY) || defined(LIBRESSL_VERSION_NUMBER)
void *reallocarray(void *, size_t, size_t);
#endif

#if !defined(HAVE_RECALLOCARRAY) || defined(LIBRESSL_VERSION_NUMBER)
void *recallocarray(void *, size_t, size_t, size_t);
#endif

#if !defined(HAVE_INET_NET_PTON) || defined(HAVE_LIBBSD)
int inet_net_pton(int, const char *, void *, size_t);
#endif

#ifndef HAVE_PLEDGE
#define pledge(promises, paths) 0
#endif

#ifndef HAVE_MALLOC_CONCEAL
#define malloc_conceal malloc
#endif

#ifndef HAVE_CALLOC_CONCEAL
#define calloc_conceal calloc
#endif

#ifndef HAVE_RES_HNOK
int res_hnok(const char *);
#endif

#if !HAVE_DECL_AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif

#if !HAVE_DECL_PF_LOCAL
#define PF_LOCAL PF_UNIX
#endif

#if !HAVE_DECL_WAIT_MYPGRP
#define WAIT_MYPGRP 0
#endif

#if !HAVE_DECL_IPPORT_HILASTAUTO
#define IPPORT_HILASTAUTO 65535
#endif

#if !HAVE_DECL_IPV6_ADDR_SCOPE_INTFACELOCAL
#define USE_IPV6_ADDR_SCOPE_NODELOCAL 1
#endif

#ifndef HAVE_SETRESGID
int setresgid(uid_t, uid_t, uid_t);
#endif

#ifndef HAVE_SETRESUID
int setresuid(uid_t, uid_t, uid_t);
#endif

#ifndef HAVE_CRYPT_CHECKPASS
int crypt_checkpass(const char *, const char *);
#endif

#ifndef HAVE_STRNDUP
char * strndup(const char *, size_t);
#endif

#ifndef HAVE_STRNLEN
size_t strnlen(const char *, size_t);
#endif

#ifndef HAVE_STRUCT_TIMEVAL
struct timeval {
	long tv_sec;
	long tv_usec;
}
#endif

#ifndef HAVE_TIMINGSAFE_MEMCMP
int timingsafe_memcmp(const void *, const void *, size_t);
#endif

#ifndef HAVE_NANOSLEEP
#ifndef HAVE_STRUCT_TIMESPEC
struct timespec {
	time_t	tv_sec;
	long	tv_nsec;
};
#endif
int nanosleep(const struct timespec *, struct timespec *);
#endif

#ifndef HAVE_SETEGID
int setegid(uid_t);
#endif

#ifndef HAVE_SETEUID
int seteuid(uid_t);
#endif

#ifndef HAVE_SETSID
#define setsid() setpgrp(0, getpid())
#endif

#ifndef HAVE_SIGNAL
typedef void (*mysig_t)(int);
mysig_t mysignal(int sig, mysig_t act);
#define signal(a,b) mysignal(a,b)
#endif

#ifndef HAVE_USLEEP
int usleep(unsigned int useconds);
#endif

int pipe2(int pipefd[2], int flags);

char *get_progname(char *);


#ifndef HAVE_CLOCK_GETTIME
#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME	0
#endif
#ifndef	CLOCK_MONOTONIC
#define CLOCK_MONOTONIC	3
#endif
int	clock_gettime(int clock_id, struct timespec *tp);
#endif

#ifndef HAVE_SUBOPTARG
#define getsubopt(optionp, tokens, valuep) openbsd_getsubopt(optionp, tokens, valuep)
int openbsd_getsubopt(char **optionp, char * const *tokens, char **valuep);
extern  char *suboptarg;               /* getsubopt(3) external variable */
#endif

#endif /* _OPENBSD_COMPAT_H */
