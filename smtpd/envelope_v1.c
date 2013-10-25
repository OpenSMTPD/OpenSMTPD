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

enum envelope_field_v1 {
	EVP_VERSION = 1,
	EVP_TAG,
	EVP_MSGID,
	EVP_TYPE,
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
	EVP_MTA_RELAY_HELO,
	EVP_BOUNCE_TYPE,
	EVP_BOUNCE_DELAY,
	EVP_BOUNCE_EXPIRE,
};

static struct field_id {
	const char	       *field;
	enum envelope_field_v1	id;
} field_ids[] = {
	{ "version",			EVP_VERSION },
	{ "tag",			EVP_TAG },
	{ "msgid",			EVP_MSGID },
	{ "type",			EVP_TYPE },
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
	{ "mta-relay-source",     	EVP_MTA_RELAY_SOURCE },
	{ "mta-relay-helo",     	EVP_MTA_RELAY_HELO },
	{ "bounce-type",		EVP_BOUNCE_TYPE },
	{ "bounce-delay",		EVP_BOUNCE_DELAY },
	{ "bounce-expire",		EVP_BOUNCE_EXPIRE },
};


static int envelope_ascii_load_v1(enum envelope_field_v1, struct envelope *, char *);
int envelope_load_buffer_v1(struct envelope *, struct dict *);

static enum envelope_field_v1
envelope_ascii_field_id(const char *field)
{
	int	i, n;

	n = sizeof(field_ids) / sizeof(struct field_id);
	for (i = 0; i < n; ++i)
 		if (strcasecmp(field, field_ids[i].field) == 0)
			return field_ids[i].id;
	return 0;
}

int
envelope_load_buffer_v1(struct envelope *ep, struct dict *d)
{
	const char	       *field;
	char		       *value;
	void		       *hdl;
	enum envelope_field_v1	id;

	hdl = NULL;
	while (dict_iter(d, &hdl, &field, (void **)&value)) {
		id = envelope_ascii_field_id(field);
		if (id == 0)
			goto err;
		if (! envelope_ascii_load_v1(id, ep, value))
			goto err;
	}
	return (1);

err:
	return (0);
}

static int
envelope_ascii_load_v1(enum envelope_field_v1 id, struct envelope *ep, char *buf)
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
        case EVP_MTA_RELAY_HELO:
                return envelope_ascii_load_string(ep->agent.mta.relay.helotable, buf,
                    sizeof ep->agent.mta.relay.helotable);
        case EVP_MTA_RELAY:
                return envelope_ascii_load_mta_relay_url(&ep->agent.mta.relay, buf);
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
