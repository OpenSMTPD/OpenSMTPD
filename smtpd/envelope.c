/*	$OpenBSD$	*/

/*
 * Copyright (c) 2011 Gilles Chehade <gilles@poolp.org>
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <inttypes.h>
#include <libgen.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "smtpd.h"
#include "log.h"

int envelope_load_buffer_v1(struct envelope *, struct dict *);
int envelope_load_buffer_v2(struct envelope *, struct dict *);

int envelope_dump_buffer_v2(const struct envelope *, char *, size_t);

void
envelope_set_errormsg(struct envelope *e, char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsnprintf(e->errorline, sizeof(e->errorline), fmt, ap);
	va_end(ap);

	/* this should not happen */
	if (ret == -1)
		err(1, "vsnprintf");

	if ((size_t)ret >= sizeof(e->errorline))
		strlcpy(e->errorline + (sizeof(e->errorline) - 4), "...", 4);
}

static int
envelope_buffer_to_dict(struct dict *d,  const char *ibuf, size_t buflen)
{
	char		lbuf[sizeof(struct envelope)], *buf;
	size_t		len;
	char	       *field, *nextline;

	bzero(lbuf, sizeof lbuf);
	if (strlcpy(lbuf, ibuf, sizeof lbuf) >= sizeof lbuf)
		goto err;
	buf = lbuf;

	while (buflen > 0) {
		len = strcspn(buf, "\n");
		buf[len] = '\0';
		nextline = buf + len + 1;
		buflen -= (nextline - buf);

		field = buf;
		while (*buf && (isalnum(*buf) || *buf == '-'))
			buf++;
		if (! *buf)
			goto err;

		/* skip whitespaces before separator */
		while (*buf && isspace(*buf))
			*buf++ = 0;

		/* we *want* ':' */
		if (*buf != ':')
			goto err;
		*buf++ = 0;

		/* skip whitespaces after separator */
		while (*buf && isspace(*buf))
			*buf++ = 0;
		dict_set(d, field, buf);
		buf = nextline;
	}

	return (1);

err:
	return (0);
}

int
envelope_load_buffer(struct envelope *ep, const char *ibuf, size_t buflen)
{
	struct dict	d;
	struct loaders {
		const char	*version;
		int	       (*loader)(struct envelope *, struct dict *);
	} loaders[] = {
		{ "1",		envelope_load_buffer_v1 },
		{ "2",		envelope_load_buffer_v2 },
	};
	const char		*version;
	int	 i;
	int	 n;
	int	 ret = 0;
	
	dict_init(&d);
	if (! envelope_buffer_to_dict(&d, ibuf, buflen))
		goto end;

	version = dict_get(&d, (void *)"version");
	if (version == NULL)
		goto end;

	n = sizeof(loaders) / sizeof(struct loaders);
	for (i = 0; i < n; ++i)
		if (strcasecmp(loaders[i].version, version) == 0)
			break;
	if (i == n)
		goto end;

	bzero(ep, sizeof *ep);
	ret = loaders[i].loader(ep, &d);

end:
	while (dict_poproot(&d, NULL, NULL))
		;
	return (ret);
}

int
envelope_dump_buffer(const struct envelope *ep, char *dest, size_t len)
{
	return envelope_dump_buffer_v2(ep, dest, len);
}

int
envelope_ascii_load_uint16(uint16_t *dest, char *buf)
{
	const char *errstr;

	*dest = strtonum(buf, 0, 0xffff, &errstr);
	if (errstr)
		return 0;
	return 1;
}

int
envelope_ascii_load_uint32(uint32_t *dest, char *buf)
{
	const char *errstr;

	*dest = strtonum(buf, 0, 0xffffffff, &errstr);
	if (errstr)
		return 0;
	return 1;
}

int
envelope_ascii_load_time(time_t *dest, char *buf)
{
	const char *errstr;

	*dest = (time_t) strtonum(buf, 0, 0x7fffffff, &errstr);
	if (errstr)
		return 0;
	return 1;
}

int
envelope_ascii_load_type(enum delivery_type *dest, char *buf)
{
	if (strcasecmp(buf, "mda") == 0)
		*dest = D_MDA;
	else if (strcasecmp(buf, "mta") == 0)
		*dest = D_MTA;
	else if (strcasecmp(buf, "bounce") == 0)
		*dest = D_BOUNCE;
	else
		return 0;
	return 1;
}

int
envelope_ascii_load_string(char *dest, char *buf, size_t len)
{
	if (strlcpy(dest, buf, len) >= len)
		return 0;
	return 1;
}

int
envelope_ascii_load_sockaddr(struct sockaddr_storage *ss, char *buf)
{
	struct sockaddr_in6 ssin6;
	struct sockaddr_in  ssin;

	bzero(&ssin, sizeof ssin);
	bzero(&ssin6, sizeof ssin6);

	if (!strcmp("local", buf)) {
		ss->ss_family = AF_LOCAL;
	}
	else if (strncasecmp("IPv6:", buf, 5) == 0) {
		if (inet_pton(AF_INET6, buf + 5, &ssin6.sin6_addr) != 1)
			return 0;
		ssin6.sin6_family = AF_INET6;
		memcpy(ss, &ssin6, sizeof(ssin6));
		ss->ss_len = sizeof(struct sockaddr_in6);
	}
	else {
		if (inet_pton(AF_INET, buf, &ssin.sin_addr) != 1)
			return 0;
		ssin.sin_family = AF_INET;
		memcpy(ss, &ssin, sizeof(ssin));
		ss->ss_len = sizeof(struct sockaddr_in);
	}
	return 1;
}

int
envelope_ascii_load_mda_method(enum action_type *dest, char *buf)
{
	if (strcasecmp(buf, "mbox") == 0)
		*dest = A_MBOX;
	else if (strcasecmp(buf, "maildir") == 0)
		*dest = A_MAILDIR;
	else if (strcasecmp(buf, "filename") == 0)
		*dest = A_FILENAME;
	else if (strcasecmp(buf, "mda") == 0)
		*dest = A_MDA;
	else if (strcasecmp(buf, "lmtp") == 0)
		*dest = A_LMTP;
	else
		return 0;
	return 1;
}

int
envelope_ascii_load_mailaddr(struct mailaddr *dest, char *buf)
{
	if (! text_to_mailaddr(dest, buf))
		return 0;
	return 1;
}

int
envelope_ascii_load_flags(enum envelope_flags *dest, char *buf)
{
	char *flag;

	while ((flag = strsep(&buf, " ,|")) != NULL) {
		if (strcasecmp(flag, "authenticated") == 0)
			*dest |= EF_AUTHENTICATED;
		else if (strcasecmp(flag, "enqueued") == 0)
			;
		else if (strcasecmp(flag, "bounce") == 0)
			*dest |= EF_BOUNCE;
		else if (strcasecmp(flag, "internal") == 0)
			*dest |= EF_INTERNAL;
		else
			return 0;
	}
	return 1;
}

int
envelope_ascii_load_mta_relay_url(struct relayhost *relay, char *buf)
{
	if (! text_to_relayhost(relay, buf))
		return 0;
	return 1;
}

int
envelope_ascii_load_mta_relay_flags(uint16_t *dest, char *buf)
{
	char *flag;

	while ((flag = strsep(&buf, " ,|")) != NULL) {
		if (strcasecmp(flag, "verify") == 0)
			*dest |= F_TLS_VERIFY;
		else if (strcasecmp(flag, "tls") == 0)
			*dest |= F_STARTTLS;
		else
			return 0;
	}

	return 1;
}


int
envelope_ascii_load_bounce_type(enum bounce_type *dest, char *buf)
{
	if (strcasecmp(buf, "error") == 0)
		*dest = B_ERROR;
	else if (strcasecmp(buf, "warn") == 0)
		*dest = B_WARNING;
	else
		return 0;
	return 1;
}

int
envelope_ascii_dump_uint16(uint16_t src, char *dest, size_t len)
{
	return bsnprintf(dest, len, "%d", src);
}

int
envelope_ascii_dump_uint32(uint32_t src, char *dest, size_t len)
{
	return bsnprintf(dest, len, "%d", src);
}

int
envelope_ascii_dump_time(time_t src, char *dest, size_t len)
{
	return bsnprintf(dest, len, "%" PRId64, (int64_t) src);
}

int
envelope_ascii_dump_string(const char *src, char *dest, size_t len)
{
	return bsnprintf(dest, len, "%s", src);
}

int
envelope_ascii_dump_type(enum delivery_type type, char *dest, size_t len)
{
	char *p = NULL;

	switch (type) {
	case D_MDA:
		p = "mda";
		break;
	case D_MTA:
		p = "mta";
		break;
	case D_BOUNCE:
		p = "bounce";
		break;
	default:
		return 0;
	}

	return bsnprintf(dest, len, "%s", p);
}

int
envelope_ascii_dump_mda_method(enum action_type type, char *dest, size_t len)
{
	char *p = NULL;

	switch (type) {
	case A_LMTP:
		p = "lmtp";
		break;
	case A_MAILDIR:
		p = "maildir";
		break;
	case A_MBOX:
		p = "mbox";
		break;
	case A_FILENAME:
		p = "filename";
		break;
	case A_MDA:
		p = "mda";
		break;
	default:
		return 0;
	}
	return bsnprintf(dest, len, "%s", p);
}

int
envelope_ascii_dump_mailaddr(const struct mailaddr *addr, char *dest, size_t len)
{
	return bsnprintf(dest, len, "%s@%s",
	    addr->user, addr->domain);
}

int
envelope_ascii_dump_flags(enum envelope_flags flags, char *buf, size_t len)
{
	size_t cpylen = 0;

	buf[0] = '\0';
	if (flags) {
		if (flags & EF_AUTHENTICATED)
			cpylen = strlcat(buf, "authenticated", len);
		if (flags & EF_BOUNCE) {
			if (buf[0] != '\0')
				strlcat(buf, " ", len);
			cpylen = strlcat(buf, "bounce", len);
		}
		if (flags & EF_INTERNAL) {
			if (buf[0] != '\0')
				strlcat(buf, " ", len);
			cpylen = strlcat(buf, "internal", len);
		}
	}

	return cpylen < len ? 1 : 0;
}

int
envelope_ascii_dump_mta_relay_url(const struct relayhost *relay, char *buf, size_t len)
{
	return bsnprintf(buf, len, "%s", relayhost_to_text(relay));
}

int
envelope_ascii_dump_mta_relay_flags(uint16_t flags, char *buf, size_t len)
{
	size_t cpylen = 0;

	buf[0] = '\0';
	if (flags) {
		if (flags & F_TLS_VERIFY) {
			if (buf[0] != '\0')
				strlcat(buf, " ", len);
			cpylen = strlcat(buf, "verify", len);
		}
		if (flags & F_STARTTLS) {
			if (buf[0] != '\0')
				strlcat(buf, " ", len);
			cpylen = strlcat(buf, "tls", len);
		}
	}

	return cpylen < len ? 1 : 0;
}

int
envelope_ascii_dump_bounce_type(enum bounce_type type, char *dest, size_t len)
{
	char *p = NULL;

	switch (type) {
	case B_ERROR:
		p = "error";
		break;
	case B_WARNING:
		p = "warn";
		break;
	default:
		return 0;
	}
	return bsnprintf(dest, len, "%s", p);
}
