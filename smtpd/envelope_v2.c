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
int envelope_load_buffer_v2(struct envelope *, struct dict *);

int
envelope_load_buffer_v2(struct envelope *ep, struct dict *d)
{
	const char	       *field;
	char		       *value;
	void		       *hdl;

	hdl = NULL;
	while (dict_iter(d, &hdl, &field, (void **)&value))
		if (! envelope_ascii_load_v2(field, ep, value))
			goto err;

	/* Transition for old envelopes */
	if (ep->smtpname[0] == 0)
		strlcpy(ep->smtpname, env->sc_hostname, sizeof(ep->smtpname));

	return (1);

err:
	return (0);
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

