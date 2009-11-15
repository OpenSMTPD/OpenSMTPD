#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "../config.h"
#include "defines.h"
#include "sys-queue.h"
#include "sys-tree.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifndef SIZE_MAX
#include <stdint.h>
#endif

/* XXX */
#ifndef MAXBSIZE
#define MAXBSIZE 4096
#endif

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
# if defined(HAVE_STRUCT_SOCKADDR_SS_LEN)
#  define SS_LEN(x)  ((x)->ss_len)
# else
#  define SS_LEN(x)  SA_LEN((struct sockaddr *)&(x))
# endif
#endif

#ifndef HAVE_SETPROCTITLE
void setproctitle(const char *fmt, ...);
#endif

#ifndef HAVE_FGETLN
char * fgetln(FILE *stream, size_t *len);
#endif

#ifndef HAVE_FPARSELN
char * fparseln(FILE *fp, size_t *size, size_t *lineno, const char str[3], int flags);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t size);
#endif

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t size);
#endif

#ifndef HAVE_STRTONUM
long long strtonum(const char *nptr, long long minval, long long maxval, const char **errstr);
#endif

#if !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)
int BSDgetopt(int argc, char * const *argv, const char *opts);
char	*BSDoptarg;		/* argument associated with option */
int	BSDoptind;		/* index into parent argv vector */
#endif


