/*	$OpenBSD$	*/

/*
 * Copyright (c) 2009 Jacek Masiulaniec <jacekm@dobremiasto.net>
 * Copyright (c) 2012 Eric Faurot <eric@openbsd.org>
 * Copyright (c) 2012 Gilles Chehade <gilles@openbsd.org>
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

#include "includes.h"

#include <sys/types.h>
#include <sys/param.h>
#include "sys-queue.h"
#include "sys-tree.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <fts.h>
#include <imsg.h>
#include <inttypes.h>
#include <libgen.h>
#include <netdb.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "smtpd.h"
#include "log.h"

static const char *in6addr_to_text(const struct in6_addr *);

const char *
sockaddr_to_text(struct sockaddr *sa)
{
	static char	buf[NI_MAXHOST];

	if (getnameinfo(sa, SA_LEN(sa), buf, sizeof(buf), NULL, 0,
	    NI_NUMERICHOST))
		return ("(unknown)");
	else
		return (buf);
}

static const char *
in6addr_to_text(const struct in6_addr *addr)
{
	struct sockaddr_in6	sa_in6;
	uint16_t		tmp16;

	bzero(&sa_in6, sizeof(sa_in6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN
	sa_in6.sin6_len = sizeof(sa_in6);
#endif
	sa_in6.sin6_family = AF_INET6;
	memcpy(&sa_in6.sin6_addr, addr, sizeof(sa_in6.sin6_addr));

	/* XXX thanks, KAME, for this ugliness... adopted from route/show.c */
	if (IN6_IS_ADDR_LINKLOCAL(&sa_in6.sin6_addr) ||
	    IN6_IS_ADDR_MC_LINKLOCAL(&sa_in6.sin6_addr)) {
		memcpy(&tmp16, &sa_in6.sin6_addr.s6_addr[2], sizeof(tmp16));
		sa_in6.sin6_scope_id = ntohs(tmp16);
		sa_in6.sin6_addr.s6_addr[2] = 0;
		sa_in6.sin6_addr.s6_addr[3] = 0;
	}

	return (sockaddr_to_text((struct sockaddr *)&sa_in6));
}

int
email_to_mailaddr(struct mailaddr *maddr, char *email)
{
	char *username;
	char *hostname;

	bzero(maddr, sizeof *maddr);

	username = email;
	hostname = strrchr(username, '@');

	if (hostname == NULL) {
		if (strlcpy(maddr->user, username, sizeof maddr->user)
		    >= sizeof maddr->user)
			return 0;
	}
	else if (username == hostname) {
		*hostname++ = '\0';
		if (strlcpy(maddr->domain, hostname, sizeof maddr->domain)
		    >= sizeof maddr->domain)
			return 0;
	}
	else {
		*hostname++ = '\0';
		if (strlcpy(maddr->user, username, sizeof maddr->user)
		    >= sizeof maddr->user)
			return 0;
		if (strlcpy(maddr->domain, hostname, sizeof maddr->domain)
		    >= sizeof maddr->domain)
			return 0;
	}	

	return 1;
}

const char *
sa_to_text(const struct sockaddr *sa)
{
	static char	 buf[NI_MAXHOST + 5];
	char		*p;

	buf[0] = '\0';
	p = buf;

	if (sa->sa_family == AF_LOCAL)
		strlcpy(buf, "local", sizeof buf);
	else if (sa->sa_family == AF_INET) {
		in_addr_t addr;

		addr = ((const struct sockaddr_in *)sa)->sin_addr.s_addr;
		addr = ntohl(addr);
		bsnprintf(p, NI_MAXHOST, "%d.%d.%d.%d",
		    (addr >> 24) & 0xff, (addr >> 16) & 0xff,
		    (addr >> 8) & 0xff, addr & 0xff);
	}
	else if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *in6;
		const struct in6_addr	*in6_addr;

		in6 = (const struct sockaddr_in6 *)sa;
		strlcpy(buf, "IPv6:", sizeof(buf));
		p = buf + 5;
		in6_addr = &in6->sin6_addr;
		bsnprintf(p, NI_MAXHOST, "%s", in6addr_to_text(in6_addr));
	}

	return (buf);
}

const char *
ss_to_text(const struct sockaddr_storage *ss)
{
	return (sa_to_text((const struct sockaddr*)ss));
}

const char *
time_to_text(time_t when)
{
	struct tm *lt;
	static char buf[40];
	char *day[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
	char *month[] = {"Jan","Feb","Mar","Apr","May","Jun",
			 "Jul","Aug","Sep","Oct","Nov","Dec"};

	lt = localtime(&when);
	if (lt == NULL || when == 0)
		fatalx("time_to_text: localtime");

	/* We do not use strftime because it is subject to locale substitution*/
	if (! bsnprintf(buf, sizeof(buf),
	    "%s, %d %s %d %02d:%02d:%02d %c%02d%02d (%s)",
	    day[lt->tm_wday], lt->tm_mday, month[lt->tm_mon],
	    lt->tm_year + 1900,
	    lt->tm_hour, lt->tm_min, lt->tm_sec,
	    lt->tm_gmtoff >= 0 ? '+' : '-',
	    abs((int)lt->tm_gmtoff / 3600),
	    abs((int)lt->tm_gmtoff % 3600) / 60,
	    lt->tm_zone))
		fatalx("time_to_text: bsnprintf");

	return buf;
}

const char *
duration_to_text(time_t t)
{
	static char	dst[64];
	char		buf[64];
	int		d, h, m, s;

	if (t == 0) {
		strlcpy(dst, "0s", sizeof dst);
		return (dst);
	}

	dst[0] = '\0';
	if (t < 0) {
		strlcpy(dst, "-", sizeof dst);
		t = -t;
	}

	s = t % 60;
	t /= 60;
	m = t % 60;
	t /= 60;
	h = t % 24;
	d = t / 24;

	if (d) {
		snprintf(buf, sizeof buf, "%id", d);
		strlcat(dst, buf, sizeof dst);
	}
	if (h) {
		snprintf(buf, sizeof buf, "%ih", h);
		strlcat(dst, buf, sizeof dst);
	}
	if (m) {
		snprintf(buf, sizeof buf, "%im", m);
		strlcat(dst, buf, sizeof dst);
	}
	if (s) {
		snprintf(buf, sizeof buf, "%is", s);
		strlcat(dst, buf, sizeof dst);
	}

	return (dst);
}

int
text_to_netaddr(struct netaddr *netaddr, const char *s)
{
	struct sockaddr_storage	ss;
	struct sockaddr_in	ssin;
	struct sockaddr_in6	ssin6;
	int			bits;

	if (strncmp("IPv6:", s, 5) == 0)
		s += 5;

	if (strchr(s, '/') != NULL) {
		/* dealing with netmask */

		bzero(&ssin, sizeof(struct sockaddr_in));
		bits = inet_net_pton(AF_INET, s, &ssin.sin_addr,
		    sizeof(struct in_addr));

		if (bits != -1) {
			ssin.sin_family = AF_INET;
			memcpy(&ss, &ssin, sizeof(ssin));
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
			ss.ss_len = sizeof(struct sockaddr_in);
#endif
		}
		else {
			bzero(&ssin6, sizeof(struct sockaddr_in6));
			bits = inet_net_pton(AF_INET6, s, &ssin6.sin6_addr,
			    sizeof(struct in6_addr));
			if (bits == -1) {
				log_warn("warn: inet_net_pton");
				return 0;
			}
			ssin6.sin6_family = AF_INET6;
			memcpy(&ss, &ssin6, sizeof(ssin6));
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
			ss.ss_len = sizeof(struct sockaddr_in6);
#endif
		}
	}
	else {
		/* IP address ? */
		if (inet_pton(AF_INET, s, &ssin.sin_addr) == 1) {
			ssin.sin_family = AF_INET;
			bits = 32;
			memcpy(&ss, &ssin, sizeof(ssin));
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
			ss.ss_len = sizeof(struct sockaddr_in);
#endif
		}
		else if (inet_pton(AF_INET6, s, &ssin6.sin6_addr) == 1) {
			ssin6.sin6_family = AF_INET6;
			bits = 128;
			memcpy(&ss, &ssin6, sizeof(ssin6));
#ifdef HAVE_STRUCT_SOCKADDR_STORAGE_SS_LEN
			ss.ss_len = sizeof(struct sockaddr_in6);
#endif
		}
		else return 0;
	}

	netaddr->ss   = ss;
	netaddr->bits = bits;
	return 1;
}

int
text_to_relayhost(struct relayhost *relay, const char *s)
{
	static const struct schema {
		const char	*name;
		uint8_t		 flags;
	} schemas [] = {
		{ "smtp://",		0				},
		{ "smtps://",		F_SMTPS				},
		{ "tls://",		F_STARTTLS			},
		{ "smtps+auth://",	F_SMTPS|F_AUTH			},
		{ "tls+auth://",	F_STARTTLS|F_AUTH		},
		{ "ssl://",		F_SMTPS|F_STARTTLS		},
		{ "ssl+auth://",	F_SMTPS|F_STARTTLS|F_AUTH	}
	};
	const char     *errstr = NULL;
	char	       *p, *q;
	char		buffer[1024];
	char	       *sep;
	size_t		i;
	int		len;

	bzero(buffer, sizeof buffer);
	if (strlcpy(buffer, s, sizeof buffer) >= sizeof buffer)
		return 0;

	for (i = 0; i < nitems(schemas); ++i)
		if (strncasecmp(schemas[i].name, s,
		    strlen(schemas[i].name)) == 0)
			break;

	if (i == nitems(schemas)) {
		/* there is a schema, but it's not recognized */
		if (strstr(buffer, "://"))
			return 0;

		/* no schema, default to smtp:// */
		i = 0;
		p = buffer;
	}
	else
		p = buffer + strlen(schemas[i].name);

	relay->flags = schemas[i].flags;

	if ((sep = strrchr(p, ':')) != NULL) {
		*sep = 0;
		relay->port = strtonum(sep+1, 1, 0xffff, &errstr);
		if (errstr)
			return 0;
		len = sep - p;
	}
	else
		len = strlen(p);

	relay->hostname[len] = 0;

	q = strchr(p, '@');
	if (q == NULL && relay->flags & F_AUTH)
		return 0;
	if (q && !(relay->flags & F_AUTH))
		return 0;

	if (q == NULL) {
		if (strlcpy(relay->hostname, p, sizeof (relay->hostname))
		    >= sizeof (relay->hostname))
			return 0;
	} else {
		*q = 0;
		if (strlcpy(relay->authlabel, p, sizeof (relay->authlabel))
		    >= sizeof (relay->authlabel))
			return 0;
		if (strlcpy(relay->hostname, q + 1, sizeof (relay->hostname))
		    >= sizeof (relay->hostname))
			return 0;
	}
	return 1;
}

const char *
relayhost_to_text(struct relayhost *relay)
{
	static char	buf[4096];
	char		port[4096];

	bzero(buf, sizeof buf);
	switch (relay->flags) {
	case F_SMTPS|F_STARTTLS|F_AUTH:
		strlcat(buf, "ssl+auth://", sizeof buf);
		break;
	case F_SMTPS|F_STARTTLS:
		strlcat(buf, "ssl://", sizeof buf);
		break;
	case F_STARTTLS|F_AUTH:
		strlcat(buf, "tls+auth://", sizeof buf);
		break;
	case F_SMTPS|F_AUTH:
		strlcat(buf, "smtps+auth://", sizeof buf);
		break;
	case F_STARTTLS:
		strlcat(buf, "tls://", sizeof buf);
		break;
	case F_SMTPS:
		strlcat(buf, "smtps://", sizeof buf);
		break;
	default:
		strlcat(buf, "smtp://", sizeof buf);
		break;
	}
	if (relay->authlabel[0]) {
		strlcat(buf, relay->authlabel, sizeof buf);
		strlcat(buf, "@", sizeof buf);
	}
	strlcat(buf, relay->hostname, sizeof buf);
	if (relay->port) {
		strlcat(buf, ":", sizeof buf);
		snprintf(port, sizeof port, "%d", relay->port);
		strlcat(buf, port, sizeof buf);
	}
	return buf;
}

uint32_t
evpid_to_msgid(uint64_t evpid)
{
	return (evpid >> 32);
}

uint64_t
msgid_to_evpid(uint32_t msgid)
{
	return ((uint64_t)msgid << 32);
}

uint64_t
text_to_evpid(const char *s)
{
	uint64_t ulval;
	char	 *ep;

	errno = 0;
	ulval = strtoull(s, &ep, 16);
	if (s[0] == '\0' || *ep != '\0')
		return 0;
	if (errno == ERANGE && ulval == ULLONG_MAX)
		return 0;
	if (ulval == 0)
		return 0;
	return (ulval);
}

uint32_t
text_to_msgid(const char *s)
{
	uint64_t ulval;
	char	 *ep;

	errno = 0;
	ulval = strtoull(s, &ep, 16);
	if (s[0] == '\0' || *ep != '\0')
		return 0;
	if (errno == ERANGE && ulval == ULLONG_MAX)
		return 0;
	if (ulval == 0)
		return 0;
	if (ulval > 0xffffffff)
		return 0;
	return (ulval & 0xffffffff);
}

const char *
rule_to_text(struct rule *r)
{
	static char buf[4096];

	bzero(buf, sizeof buf);
	strlcpy(buf, r->r_decision == R_ACCEPT  ? "accept" : "reject", sizeof buf);
	if (r->r_tag[0]) {
		strlcat(buf, " on ", sizeof buf);
		strlcat(buf, r->r_tag, sizeof buf);
	}
	strlcat(buf, " from ", sizeof buf);
	strlcat(buf, r->r_sources->t_name, sizeof buf);

	switch (r->r_desttype) {
	case DEST_DOM:
		if (r->r_destination == NULL) {
			strlcat(buf, " for any", sizeof buf);
			break;
		}
		strlcat(buf, " for domain ", sizeof buf);
		strlcat(buf, r->r_destination->t_name, sizeof buf);
		if (r->r_mapping) {
			strlcat(buf, " alias ", sizeof buf);
			strlcat(buf, r->r_mapping->t_name, sizeof buf);
		}
		break;
	case DEST_VDOM:
		if (r->r_destination == NULL) {
			strlcat(buf, " for any virtual ", sizeof buf);
			strlcat(buf, r->r_mapping->t_name, sizeof buf);
			break;
		}
		strlcat(buf, " for domain ", sizeof buf);
		strlcat(buf, r->r_destination->t_name, sizeof buf);
		strlcat(buf, " virtual ", sizeof buf);
		strlcat(buf, r->r_mapping->t_name, sizeof buf);
		break;
	}

	switch (r->r_action) {
	case A_RELAY:
		strlcat(buf, " relay", sizeof buf);
		break;
	case A_RELAYVIA:
		strlcat(buf, " relay via ", sizeof buf);
		strlcat(buf, relayhost_to_text(&r->r_value.relayhost), sizeof buf);
		break;
	case A_MAILDIR:
		strlcat(buf, " deliver to maildir \"", sizeof buf);
		strlcat(buf, r->r_value.buffer, sizeof buf);
		strlcat(buf, "\"", sizeof buf);
		break;
	case A_MBOX:
		strlcat(buf, " deliver to mbox", sizeof buf);
		break;
	case A_FILENAME:
		strlcat(buf, " deliver to filename \"", sizeof buf);
		strlcat(buf, r->r_value.buffer, sizeof buf);
		strlcat(buf, "\"", sizeof buf);
		break;
	case A_MDA:
		strlcat(buf, " deliver to mda \"", sizeof buf);
		strlcat(buf, r->r_value.buffer, sizeof buf);
		strlcat(buf, "\"", sizeof buf);
		break;
	}
	    
	return buf;
}

int
text_to_userinfo(struct userinfo *userinfo, const char *s)
{
	char		buf[MAXPATHLEN];
	char	       *p;
	const char     *errstr;

	bzero(buf, sizeof buf);
	p = buf;
	while (*s && *s != ':')
		*p++ = *s++;
	if (*s++ != ':')
		goto error;

	if (strlcpy(userinfo->username, buf,
		sizeof userinfo->username) >= sizeof userinfo->username)
		goto error;

	bzero(buf, sizeof buf);
	p = buf;
	while (*s && *s != ':')
		*p++ = *s++;
	if (*s++ != ':')
		goto error;
	userinfo->uid = strtonum(buf, 0, UINT_MAX, &errstr);
	if (errstr)
		goto error;

	bzero(buf, sizeof buf);
	p = buf;
	while (*s && *s != ':')
		*p++ = *s++;
	if (*s++ != ':')
		goto error;
	userinfo->gid = strtonum(buf, 0, UINT_MAX, &errstr);
	if (errstr)
		goto error;

	if (strlcpy(userinfo->directory, s,
		sizeof userinfo->directory) >= sizeof userinfo->directory)
		goto error;

	return 1;

error:
	return 0;
}
