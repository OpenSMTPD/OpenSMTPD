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

static int envelope_ascii_load_v2(const char *, struct envelope *, char *);
static int envelope_ascii_dump_v2(const char *, const struct envelope *, char *, size_t);
static void envelope_dump2(const struct envelope *, char **, size_t *, const char *);
int envelope_load_buffer_v2(struct envelope *, struct dict *);
int envelope_dump_buffer_v2(const struct envelope *, char *, size_t);

int
envelope_load_buffer_v2(struct envelope *ep, struct dict *d)
{
	const char	       *field;
	char		       *value;
	void		       *hdl;

	hdl = NULL;
	while (dict_iter(d, &hdl, &field, (void **)&value)) {
		if (! envelope_ascii_load_v2(field, ep, value))
			goto err;
	}

	/* Transition for old envelopes */
        if (ep->smtpname[0] == 0)
                strlcpy(ep->smtpname, env->sc_hostname, sizeof(ep->smtpname));

	return (1);

err:
	return (0);
}


int
envelope_dump_buffer_v2(const struct envelope *ep, char *dest, size_t len)
{
	char	*p = dest;

	envelope_dump2(ep, &dest, &len, "version");
	envelope_dump2(ep, &dest, &len, "tag");
	envelope_dump2(ep, &dest, &len, "type");
	envelope_dump2(ep, &dest, &len, "smtpname");
	envelope_dump2(ep, &dest, &len, "helo");
	envelope_dump2(ep, &dest, &len, "hostname");
	envelope_dump2(ep, &dest, &len, "errorline");
	envelope_dump2(ep, &dest, &len, "sockaddr");
	envelope_dump2(ep, &dest, &len, "sender");
	envelope_dump2(ep, &dest, &len, "rcpt");
	envelope_dump2(ep, &dest, &len, "dest");
	envelope_dump2(ep, &dest, &len, "ctime");
	envelope_dump2(ep, &dest, &len, "last-try");
	envelope_dump2(ep, &dest, &len, "last-bounce");
	envelope_dump2(ep, &dest, &len, "expire");
	envelope_dump2(ep, &dest, &len, "retry");
	envelope_dump2(ep, &dest, &len, "flags");

	switch (ep->type) {
	case D_MDA:
		envelope_dump2(ep, &dest, &len, "mda-method");
		envelope_dump2(ep, &dest, &len, "mda-usertable");
		envelope_dump2(ep, &dest, &len, "mda-buffer");
		envelope_dump2(ep, &dest, &len, "mda-user");
		break;
	case D_MTA:
		envelope_dump2(ep, &dest, &len, "mta-relay");
		envelope_dump2(ep, &dest, &len, "mta-relay-source");
		envelope_dump2(ep, &dest, &len, "mta-relay-cert");
		envelope_dump2(ep, &dest, &len, "mta-relay-auth");
		envelope_dump2(ep, &dest, &len, "mta-relay-heloname");
		envelope_dump2(ep, &dest, &len, "mta-relay-helotable");
		envelope_dump2(ep, &dest, &len, "mta-relay-flags");
		break;
	case D_BOUNCE:
		envelope_dump2(ep, &dest, &len, "bounce-type");
		envelope_dump2(ep, &dest, &len, "bounce-delay");
		envelope_dump2(ep, &dest, &len, "bounce-expire");
		break;
	default:
		return (0);
	}

	if (dest == NULL)
		return (0);

	return (dest - p);
}


static void
envelope_dump2(const struct envelope *ep, char **dest, size_t *len, const char *field)
{
	char	buf[8192];
	int	l;

	if (*dest == NULL)
		return;

	bzero(buf, sizeof buf);
	if (! envelope_ascii_dump_v2(field, ep, buf, sizeof buf))
		goto err;
	if (buf[0] == '\0')
		return;

	l = snprintf(*dest, *len, "%s: %s\n", field, buf);
	if (l == -1 || (size_t) l >= *len)
		goto err;
	*dest += l;
	*len -= l;

	return;
err:
	*dest = NULL;
}

static int
envelope_ascii_load_v2(const char *field, struct envelope *ep, char *buf)
{
	if (strcasecmp("version", field) == 0)
		return envelope_ascii_load_uint32(&ep->version, buf);

	if (strcasecmp("tag", field) == 0)
		return envelope_ascii_load_string(ep->tag, buf, sizeof ep->tag);

	if (strcasecmp("msgid", field) == 0)
		return 1;

	if (strcasecmp("type", field) == 0)
		return envelope_ascii_load_type(&ep->type, buf);

	if (strcasecmp("smtpname", field) == 0)
		return envelope_ascii_load_string(ep->smtpname, buf, sizeof(ep->smtpname));

	if (strcasecmp("helo", field) == 0)
		return envelope_ascii_load_string(ep->helo, buf, sizeof ep->helo);

	if (strcasecmp("hostname", field) == 0)
		return envelope_ascii_load_string(ep->hostname, buf,
		    sizeof ep->hostname);

	if (strcasecmp("errorline", field) == 0)
		return envelope_ascii_load_string(ep->errorline, buf,
		    sizeof ep->errorline);

	if (strcasecmp("sockaddr", field) == 0)
		return envelope_ascii_load_sockaddr(&ep->ss, buf);

	if (strcasecmp("sender", field) == 0)
		return envelope_ascii_load_mailaddr(&ep->sender, buf);

	if (strcasecmp("rcpt", field) == 0)
		return envelope_ascii_load_mailaddr(&ep->rcpt, buf);

	if (strcasecmp("dest", field) == 0)
		return envelope_ascii_load_mailaddr(&ep->dest, buf);

	if (strcasecmp("mda-method", field) == 0)
		return envelope_ascii_load_mda_method(&ep->agent.mda.method, buf);

	if (strcasecmp("mda-buffer", field) == 0)
		return envelope_ascii_load_string(ep->agent.mda.buffer, buf,
		    sizeof ep->agent.mda.buffer);

	if (strcasecmp("mda-user", field) == 0)
		return envelope_ascii_load_string(ep->agent.mda.username, buf,
		    sizeof ep->agent.mda.username);

	if (strcasecmp("mda-usertable", field) == 0)
		return envelope_ascii_load_string(ep->agent.mda.usertable, buf,
		    sizeof ep->agent.mda.usertable);

	if (strcasecmp("mta-relay-source", field) == 0)
		return envelope_ascii_load_string(ep->agent.mta.relay.sourcetable, buf,
		    sizeof ep->agent.mta.relay.sourcetable);

	if (strcasecmp("mta-relay-cert", field) == 0)
		return envelope_ascii_load_string(ep->agent.mta.relay.cert, buf,
		    sizeof ep->agent.mta.relay.cert);

	if (strcasecmp("mta-relay-auth", field) == 0)
		return envelope_ascii_load_string(ep->agent.mta.relay.authtable, buf,
		    sizeof ep->agent.mta.relay.authtable);

	if (strcasecmp("mta-relay-heloname", field) == 0)
		return envelope_ascii_load_string(ep->agent.mta.relay.heloname, buf,
		    sizeof ep->agent.mta.relay.heloname);

	if (strcasecmp("mta-relay-helotable", field) == 0)
		return envelope_ascii_load_string(ep->agent.mta.relay.helotable, buf,
		    sizeof ep->agent.mta.relay.helotable);

	if (strcasecmp("mta-relay-flags", field) == 0)
		return envelope_ascii_load_mta_relay_flags(&ep->agent.mta.relay.flags, buf);

	if (strcasecmp("mta-relay", field) == 0) {
		int ret;
		uint16_t flags = ep->agent.mta.relay.flags;
		ret = envelope_ascii_load_mta_relay_url(&ep->agent.mta.relay, buf);
		if (! ret)
			return 0;
		ep->agent.mta.relay.flags |= flags;
		return ret;
	}

	if (strcasecmp("ctime", field) == 0)
		return envelope_ascii_load_time(&ep->creation, buf);

	if (strcasecmp("expire", field) == 0)
		return envelope_ascii_load_time(&ep->expire, buf);

	if (strcasecmp("retry", field) == 0)
		return envelope_ascii_load_uint16(&ep->retry, buf);

	if (strcasecmp("last-try", field) == 0)
		return envelope_ascii_load_time(&ep->lasttry, buf);

	if (strcasecmp("last-bounce", field) == 0)
		return envelope_ascii_load_time(&ep->lastbounce, buf);

	if (strcasecmp("flags", field) == 0)
		return envelope_ascii_load_flags(&ep->flags, buf);

	if (strcasecmp("bounce-type", field) == 0)
		return envelope_ascii_load_bounce_type(&ep->agent.bounce.type, buf);

	if (strcasecmp("bounce-delay", field) == 0)
		return envelope_ascii_load_time(&ep->agent.bounce.delay, buf);

	if (strcasecmp("bounce-expire", field) == 0)
		return envelope_ascii_load_time(&ep->agent.bounce.expire, buf);

	return 0;
}


static int
envelope_ascii_dump_v2(const char *field, const struct envelope *ep,
    char *buf, size_t len)
{
	if (strcasecmp(field, "version") == 0)
		return envelope_ascii_dump_uint32(SMTPD_ENVELOPE_VERSION, buf, len);

	if (strcasecmp(field, "tag") == 0)
		return envelope_ascii_dump_string(ep->tag, buf, len);

	if (strcasecmp(field, "msgid") == 0)
		return 1;

	if (strcasecmp(field, "type") == 0)
		return envelope_ascii_dump_type(ep->type, buf, len);

	if (strcasecmp(field, "smtpname") == 0)
		return envelope_ascii_dump_string(ep->smtpname, buf, len);

	if (strcasecmp(field, "helo") == 0)
		return envelope_ascii_dump_string(ep->helo, buf, len);

	if (strcasecmp(field, "hostname") == 0)
		return envelope_ascii_dump_string(ep->hostname, buf, len);

	if (strcasecmp(field, "errorline") == 0)
		return envelope_ascii_dump_string(ep->errorline, buf, len);

	if (strcasecmp(field, "sockaddr") == 0)
		return envelope_ascii_dump_string(ss_to_text(&ep->ss), buf, len);

	if (strcasecmp(field, "sender") == 0)
		return envelope_ascii_dump_mailaddr(&ep->sender, buf, len);

	if (strcasecmp(field, "rcpt") == 0)
		return envelope_ascii_dump_mailaddr(&ep->rcpt, buf, len);

	if (strcasecmp(field, "dest") == 0)
		return envelope_ascii_dump_mailaddr(&ep->dest, buf, len);

	if (strcasecmp(field, "ctime") == 0)
		return envelope_ascii_dump_time(ep->creation, buf, len);

	if (strcasecmp(field, "expire") == 0)
		return envelope_ascii_dump_time(ep->expire, buf, len);

	if (strcasecmp(field, "retry") == 0)
		return envelope_ascii_dump_uint16(ep->retry, buf, len);

	if (strcasecmp(field, "last-try") == 0)
		return envelope_ascii_dump_time(ep->lasttry, buf, len);

	if (strcasecmp(field, "last-bounce") == 0)
		return envelope_ascii_dump_time(ep->lastbounce, buf, len);

	if (strcasecmp(field, "flags") == 0)
		return envelope_ascii_dump_flags(ep->flags, buf, len);

	if (strcasecmp(field, "mda-method") == 0)
		return envelope_ascii_dump_mda_method(ep->agent.mda.method, buf, len);

	if (strcasecmp(field, "mda-buffer") == 0)
		return envelope_ascii_dump_string(ep->agent.mda.buffer, buf, len);

	if (strcasecmp(field, "mda-user") == 0)
		return envelope_ascii_dump_string(ep->agent.mda.username, buf, len);

	if (strcasecmp(field, "mda-usertable") == 0)
		return envelope_ascii_dump_string(ep->agent.mda.usertable, buf, len);

	if (strcasecmp(field, "mta-relay") == 0) {
		if (ep->agent.mta.relay.hostname[0])
			return envelope_ascii_dump_mta_relay_url(&ep->agent.mta.relay, buf, len);
		return 1;
	}

	if (strcasecmp(field, "mta-relay-auth") == 0)
		return envelope_ascii_dump_string(ep->agent.mta.relay.authtable,
		    buf, len);

	if (strcasecmp(field, "mta-relay-cert") == 0)
		return envelope_ascii_dump_string(ep->agent.mta.relay.cert,
		    buf, len);

	if (strcasecmp(field, "mta-relay-flags") == 0)
		return envelope_ascii_dump_mta_relay_flags(ep->agent.mta.relay.flags,
		    buf, len);

	if (strcasecmp(field, "mta-relay-source") == 0)
		return envelope_ascii_dump_string(ep->agent.mta.relay.sourcetable,
		    buf, len);

	if (strcasecmp(field, "mta-relay-heloname") == 0)
		return envelope_ascii_dump_string(ep->agent.mta.relay.heloname,
		    buf, len);

	if (strcasecmp(field, "mta-relay-helotable") == 0)
		return envelope_ascii_dump_string(ep->agent.mta.relay.helotable,
		    buf, len);

	if (strcasecmp(field, "bounce-type") == 0)
		return envelope_ascii_dump_bounce_type(ep->agent.bounce.type, buf, len);

	if (strcasecmp(field, "bounce-delay") == 0) {
		if (ep->agent.bounce.type != B_WARNING)
			return (1);
		return envelope_ascii_dump_time(ep->agent.bounce.delay, buf, len);
	}

	if (strcasecmp(field, "bounce-expire") == 0) {
		if (ep->agent.bounce.type != B_WARNING)
			return (1);
		return envelope_ascii_dump_time(ep->agent.bounce.expire, buf, len);
	}

	return 0;
}
