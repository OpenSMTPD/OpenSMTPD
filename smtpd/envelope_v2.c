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

enum envelope_field_v2 {
	EVP_VERSION = 1,
	EVP_TAG,
	EVP_MSGID,
	EVP_TYPE,
	EVP_SMTPNAME,
	EVP_HELO,
	EVP_HOSTNAME,
	EVP_ERRORLINE,
	EVP_SOCKADDR,
	EVP_SENDER,
	EVP_RCPT,
	EVP_DEST,
	EVP_CTIME,
	EVP_EXPIRE,
	EVP_RETRY,
	EVP_LASTTRY,
	EVP_LASTBOUNCE,
	EVP_FLAGS,
	EVP_MDA_METHOD,
	EVP_MDA_BUFFER,
	EVP_MDA_USER,
	EVP_MDA_USERTABLE,
	EVP_MTA_RELAY,
	EVP_MTA_RELAY_AUTH,
	EVP_MTA_RELAY_CERT,
	EVP_MTA_RELAY_SOURCE,
	EVP_MTA_RELAY_HELONAME,
	EVP_MTA_RELAY_HELOTABLE,
	EVP_MTA_RELAY_FLAGS,
	EVP_BOUNCE_TYPE,
	EVP_BOUNCE_DELAY,
	EVP_BOUNCE_EXPIRE,
};

static struct field_id {
	const char	       *field;
	enum envelope_field_v2	id;
} field_ids[] = {
	{ "version",			EVP_VERSION },
	{ "tag",			EVP_TAG },
	{ "msgid",			EVP_MSGID },
	{ "type",			EVP_TYPE },
	{ "smtpname",			EVP_SMTPNAME },
	{ "helo",			EVP_HELO },
	{ "hostname",			EVP_HOSTNAME },
	{ "errorline",			EVP_ERRORLINE },
	{ "sockaddr",			EVP_SOCKADDR },
	{ "sender",			EVP_SENDER },
	{ "rcpt",			EVP_RCPT },
	{ "dest",			EVP_DEST },
	{ "ctime",			EVP_CTIME },
	{ "expire",			EVP_EXPIRE },
	{ "retry",			EVP_RETRY },
	{ "last-try",			EVP_LASTTRY },
	{ "last-bounce",		EVP_LASTBOUNCE },
	{ "flags",			EVP_FLAGS },
	{ "mda-method",			EVP_MDA_METHOD },
	{ "mda-buffer",			EVP_MDA_BUFFER },
	{ "mda-user",			EVP_MDA_USER },
	{ "mda-usertable",	     	EVP_MDA_USERTABLE },
	{ "mta-relay",			EVP_MTA_RELAY },
	{ "mta-relay-auth",     	EVP_MTA_RELAY_AUTH },
	{ "mta-relay-cert",     	EVP_MTA_RELAY_CERT },
	{ "mta-relay-flags",     	EVP_MTA_RELAY_FLAGS },
	{ "mta-relay-source",     	EVP_MTA_RELAY_SOURCE },
	{ "mta-relay-heloname",     	EVP_MTA_RELAY_HELONAME },
	{ "mta-relay-helotable",     	EVP_MTA_RELAY_HELOTABLE  },
	{ "bounce-type",		EVP_BOUNCE_TYPE },
	{ "bounce-delay",		EVP_BOUNCE_DELAY },
	{ "bounce-expire",		EVP_BOUNCE_EXPIRE },
};


static int envelope_ascii_load_v2(enum envelope_field_v2, struct envelope *, char *);
static int envelope_ascii_dump_v2(enum envelope_field_v2, const struct envelope *, char *, size_t);
int envelope_load_buffer_v2(struct envelope *, struct dict *);
int envelope_dump_buffer_v2(const struct envelope *, char *, size_t);

static enum envelope_field_v2
envelope_ascii_field_id(const char *field)
{
	int	i, n;

	n = sizeof(field_ids) / sizeof(struct field_id);
	for (i = 0; i < n; ++i)
		if (strcasecmp(field, field_ids[i].field) == 0)
			return field_ids[i].id;
	return 0;
}

static const char *
envelope_ascii_field_name(enum envelope_field_v2 id)
{
	int	i, n;

	n = sizeof(field_ids) / sizeof(struct field_id);
	for (i = 0; i < n; ++i)
		if (id == field_ids[i].id)
			return field_ids[i].field;
	return NULL;
}


int
envelope_load_buffer_v2(struct envelope *ep, struct dict *d)
{
	const char	       *field;
	char		       *value;
	void		       *hdl;
	enum envelope_field_v2	id;

	hdl = NULL;
	while (dict_iter(d, &hdl, &field, (void **)&value)) {
		id = envelope_ascii_field_id(field);
		if (id == 0)
			goto err;
		if (! envelope_ascii_load_v2(id, ep, value))
			goto err;
	}
	return (1);

err:
	return (0);
}


int
envelope_dump_buffer_v2(const struct envelope *ep, char *dest, size_t len)
{
	char	buf[8192];

	enum envelope_field_v2 fields[] = {
		EVP_VERSION,
		EVP_TAG,
		EVP_TYPE,
		EVP_SMTPNAME,
		EVP_HELO,
		EVP_HOSTNAME,
		EVP_ERRORLINE,
		EVP_SOCKADDR,
		EVP_SENDER,
		EVP_RCPT,
		EVP_DEST,
		EVP_CTIME,
		EVP_LASTTRY,
		EVP_LASTBOUNCE,
		EVP_EXPIRE,
		EVP_RETRY,
		EVP_FLAGS
	};
	enum envelope_field_v2 mda_fields[] = {
		EVP_MDA_METHOD,
		EVP_MDA_USERTABLE,
		EVP_MDA_BUFFER,
		EVP_MDA_USER
	};
	enum envelope_field_v2 mta_fields[] = {
		EVP_MTA_RELAY_SOURCE,
		EVP_MTA_RELAY_CERT,
		EVP_MTA_RELAY_AUTH,
		EVP_MTA_RELAY_HELONAME,
		EVP_MTA_RELAY_HELOTABLE,
		EVP_MTA_RELAY_FLAGS,
		EVP_MTA_RELAY,
	};
	enum envelope_field_v2 bounce_fields[] = {
		EVP_BOUNCE_TYPE,
		EVP_BOUNCE_DELAY,
		EVP_BOUNCE_EXPIRE,
	};
	enum envelope_field_v2 *pfields = NULL;
	int	 i, n, l;
	char	*p;

	p = dest;
	n = sizeof(fields) / sizeof(enum envelope_field_v2);
	for (i = 0; i < n; ++i) {
		bzero(buf, sizeof buf);
		if (! envelope_ascii_dump_v2(fields[i], ep, buf, sizeof buf))
			goto err;
		if (buf[0] == '\0')
			continue;

		l = snprintf(dest, len, "%s: %s\n",
			envelope_ascii_field_name(fields[i]), buf);
		if (l == -1 || (size_t) l >= len)
			goto err;
		dest += l;
		len -= l;
	}

	switch (ep->type) {
	case D_MDA:
		pfields = mda_fields;
		n = sizeof(mda_fields) / sizeof(enum envelope_field_v2);
		break;
	case D_MTA:
		pfields = mta_fields;
		n = sizeof(mta_fields) / sizeof(enum envelope_field_v2);
		break;
	case D_BOUNCE:
		pfields = bounce_fields;
		n = sizeof(bounce_fields) / sizeof(enum envelope_field_v2);
		break;
	default:
		goto err;
	}

	if (pfields) {
		for (i = 0; i < n; ++i) {
			bzero(buf, sizeof buf);
			if (! envelope_ascii_dump_v2(pfields[i], ep, buf,
				sizeof buf))
				goto err;
			if (buf[0] == '\0')
				continue;

			l = snprintf(dest, len, "%s: %s\n",
				envelope_ascii_field_name(pfields[i]), buf);
			if (l == -1 || (size_t) l >= len)
				goto err;
			dest += l;
			len -= l;
		}
	}

	return (dest - p);

err:
	return (0);
}


static int
envelope_ascii_load_v2(enum envelope_field_v2 id, struct envelope *ep, char *buf)
{
	switch (id) {
	case EVP_VERSION:
		return envelope_ascii_load_uint32(&ep->version, buf);
	case EVP_TAG:
		return envelope_ascii_load_string(ep->tag, buf, sizeof ep->tag);
	case EVP_MSGID:
		return 1;
	case EVP_TYPE:
		return envelope_ascii_load_type(&ep->type, buf);
	case EVP_SMTPNAME:
		return envelope_ascii_load_string(ep->smtpname, buf, sizeof(ep->smtpname));
	case EVP_HELO:
		return envelope_ascii_load_string(ep->helo, buf, sizeof ep->helo);
	case EVP_HOSTNAME:
		return envelope_ascii_load_string(ep->hostname, buf,
		    sizeof ep->hostname);
	case EVP_ERRORLINE:
		return envelope_ascii_load_string(ep->errorline, buf,
		    sizeof ep->errorline);
	case EVP_SOCKADDR:
		return envelope_ascii_load_sockaddr(&ep->ss, buf);
	case EVP_SENDER:
		return envelope_ascii_load_mailaddr(&ep->sender, buf);
	case EVP_RCPT:
		return envelope_ascii_load_mailaddr(&ep->rcpt, buf);
	case EVP_DEST:
		return envelope_ascii_load_mailaddr(&ep->dest, buf);
	case EVP_MDA_METHOD:
		return envelope_ascii_load_mda_method(&ep->agent.mda.method, buf);
	case EVP_MDA_BUFFER:
		return envelope_ascii_load_string(ep->agent.mda.buffer, buf,
		    sizeof ep->agent.mda.buffer);
	case EVP_MDA_USER:
		return envelope_ascii_load_string(ep->agent.mda.username, buf,
		    sizeof ep->agent.mda.username);
	case EVP_MDA_USERTABLE:
		return envelope_ascii_load_string(ep->agent.mda.usertable, buf,
		    sizeof ep->agent.mda.usertable);
	case EVP_MTA_RELAY_SOURCE:
		return envelope_ascii_load_string(ep->agent.mta.relay.sourcetable, buf,
		    sizeof ep->agent.mta.relay.sourcetable);
	case EVP_MTA_RELAY_CERT:
		return envelope_ascii_load_string(ep->agent.mta.relay.cert, buf,
		    sizeof ep->agent.mta.relay.cert);
	case EVP_MTA_RELAY_AUTH:
		return envelope_ascii_load_string(ep->agent.mta.relay.authtable, buf,
		    sizeof ep->agent.mta.relay.authtable);
	case EVP_MTA_RELAY_HELONAME:
		return envelope_ascii_load_string(ep->agent.mta.relay.heloname, buf,
		    sizeof ep->agent.mta.relay.heloname);
	case EVP_MTA_RELAY_HELOTABLE:
		return envelope_ascii_load_string(ep->agent.mta.relay.helotable, buf,
		    sizeof ep->agent.mta.relay.helotable);
	case EVP_MTA_RELAY_FLAGS:
		return envelope_ascii_load_mta_relay_flags(&ep->agent.mta.relay.flags, buf);
	case EVP_MTA_RELAY: {
		int ret;
		uint16_t flags = ep->agent.mta.relay.flags;
		ret = envelope_ascii_load_mta_relay_url(&ep->agent.mta.relay, buf);
		if (! ret)
			break;
		ep->agent.mta.relay.flags |= flags;
		return ret;
	}
	case EVP_CTIME:
		return envelope_ascii_load_time(&ep->creation, buf);
	case EVP_EXPIRE:
		return envelope_ascii_load_time(&ep->expire, buf);
	case EVP_RETRY:
		return envelope_ascii_load_uint16(&ep->retry, buf);
	case EVP_LASTTRY:
		return envelope_ascii_load_time(&ep->lasttry, buf);
	case EVP_LASTBOUNCE:
		return envelope_ascii_load_time(&ep->lastbounce, buf);
	case EVP_FLAGS:
		return envelope_ascii_load_flags(&ep->flags, buf);
	case EVP_BOUNCE_TYPE:
		return envelope_ascii_load_bounce_type(&ep->agent.bounce.type, buf);
	case EVP_BOUNCE_DELAY:
		return envelope_ascii_load_time(&ep->agent.bounce.delay, buf);
	case EVP_BOUNCE_EXPIRE:
		return envelope_ascii_load_time(&ep->agent.bounce.expire, buf);
	}
	return 0;
}


static int
envelope_ascii_dump_v2(enum envelope_field_v2 id, const struct envelope *ep,
    char *buf, size_t len)
{
	switch (id) {
	case EVP_VERSION:
		return envelope_ascii_dump_uint32(SMTPD_ENVELOPE_VERSION, buf, len);
	case EVP_TAG:
		return envelope_ascii_dump_string(ep->tag, buf, len);
	case EVP_MSGID:
		return 1;
	case EVP_TYPE:
		return envelope_ascii_dump_type(ep->type, buf, len);
	case EVP_SMTPNAME:
		return envelope_ascii_dump_string(ep->smtpname, buf, len);
	case EVP_HELO:
		return envelope_ascii_dump_string(ep->helo, buf, len);
	case EVP_HOSTNAME:
		return envelope_ascii_dump_string(ep->hostname, buf, len);
	case EVP_ERRORLINE:
		return envelope_ascii_dump_string(ep->errorline, buf, len);
	case EVP_SOCKADDR:
		return envelope_ascii_dump_string(ss_to_text(&ep->ss), buf, len);
	case EVP_SENDER:
		return envelope_ascii_dump_mailaddr(&ep->sender, buf, len);
	case EVP_RCPT:
		return envelope_ascii_dump_mailaddr(&ep->rcpt, buf, len);
	case EVP_DEST:
		return envelope_ascii_dump_mailaddr(&ep->dest, buf, len);
	case EVP_MDA_METHOD:
		return envelope_ascii_dump_mda_method(ep->agent.mda.method, buf, len);
	case EVP_MDA_BUFFER:
		return envelope_ascii_dump_string(ep->agent.mda.buffer, buf, len);
	case EVP_MDA_USER:
		return envelope_ascii_dump_string(ep->agent.mda.username, buf, len);
	case EVP_MDA_USERTABLE:
		return envelope_ascii_dump_string(ep->agent.mda.usertable, buf, len);
	case EVP_MTA_RELAY_SOURCE:
		return envelope_ascii_dump_string(ep->agent.mta.relay.sourcetable,
		    buf, len);
	case EVP_MTA_RELAY_CERT:
		return envelope_ascii_dump_string(ep->agent.mta.relay.cert,
		    buf, len);
	case EVP_MTA_RELAY_AUTH:
		return envelope_ascii_dump_string(ep->agent.mta.relay.authtable,
		    buf, len);
	case EVP_MTA_RELAY_HELONAME:
		return envelope_ascii_dump_string(ep->agent.mta.relay.heloname,
		    buf, len);
	case EVP_MTA_RELAY_HELOTABLE:
		return envelope_ascii_dump_string(ep->agent.mta.relay.helotable,
		    buf, len);
	case EVP_MTA_RELAY_FLAGS:
		return envelope_ascii_dump_mta_relay_flags(ep->agent.mta.relay.flags,
		    buf, len);
	case EVP_MTA_RELAY:
		if (ep->agent.mta.relay.hostname[0])
			return envelope_ascii_dump_mta_relay_url(&ep->agent.mta.relay, buf, len);
		return 1;
	case EVP_CTIME:
		return envelope_ascii_dump_time(ep->creation, buf, len);
	case EVP_EXPIRE:
		return envelope_ascii_dump_time(ep->expire, buf, len);
	case EVP_RETRY:
		return envelope_ascii_dump_uint16(ep->retry, buf, len);
	case EVP_LASTTRY:
		return envelope_ascii_dump_time(ep->lasttry, buf, len);
	case EVP_LASTBOUNCE:
		return envelope_ascii_dump_time(ep->lastbounce, buf, len);
	case EVP_FLAGS:
		return envelope_ascii_dump_flags(ep->flags, buf, len);
	case EVP_BOUNCE_TYPE:
		return envelope_ascii_dump_bounce_type(ep->agent.bounce.type, buf, len);
	case EVP_BOUNCE_DELAY:
		if (ep->agent.bounce.type != B_WARNING)
			return (1);
		return envelope_ascii_dump_time(ep->agent.bounce.delay, buf, len);
	case EVP_BOUNCE_EXPIRE:
		if (ep->agent.bounce.type != B_WARNING)
			return (1);
		return envelope_ascii_dump_time(ep->agent.bounce.expire, buf, len);
	}
	return 0;
}
