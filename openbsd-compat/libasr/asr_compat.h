/*
 * Copyright (c) 2018 Eric Faurot <eric@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


/* source compat */
#define ASR_BUFSIZ	1024

#define DEF_WEAK(x)
#define __THREAD_NAME(x) __thread_name_ ## x

#ifndef __BEGIN_HIDDEN_DECLS
#define __BEGIN_HIDDEN_DECLS
#endif
#ifndef __END_HIDDEN_DECLS
#define __END_HIDDEN_DECLS
#endif

/*
 * netdb.h
 */
#ifndef NETDB_SUCCESS
#define NETDB_SUCCESS 0
#endif

#ifndef NETDB_INTERNAL
#define NETDB_INTERNAL -1
#endif

#ifndef AI_FQDN
#define AI_FQDN AI_CANONNAME
#endif

#ifndef AI_MASK
#define AI_MASK \
    (AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST | AI_NUMERICSERV | AI_ADDRCONFIG | AI_FQDN)
#endif

#ifndef SCOPE_DELIMITER
#define SCOPE_DELIMITER '%'
#endif

#ifndef _PATH_HOSTS
#define _PATH_HOSTS "/etc/hosts"
#endif

#ifndef _PATH_NETWORKS
#define _PATH_NETWORKS "/etc/networks"
#endif

/*
 * arpa/nameserv.h
 */
#ifndef T_OPT
#define T_OPT 41
#endif

#ifndef	DNS_MESSAGEEXTFLAG_DO
#define	DNS_MESSAGEEXTFLAG_DO	0x8000U
#endif

#ifndef HAVE___P_CLASS
const char * __p_class(int);
#endif

#ifndef HAVE___P_TYPE
const char * __p_type(int);
#endif
