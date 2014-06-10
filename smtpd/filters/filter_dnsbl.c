/*      $OpenBSD$   */

/*
 * Copyright (c) 2013 Eric Faurot <eric@openbsd.org>
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
#include <sys/socket.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <event.h>
#include <asr.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

const char * dnsbl_host = "dnsbl.sorbs.net";

static void
dnsbl_event_dispatch(struct asr_result *ar, void *arg)
{
	uint64_t *q = arg;

	if (ar->ar_addrinfo)
		freeaddrinfo(ar->ar_addrinfo);

	if (ar->ar_gai_errno != EAI_NODATA)
		filter_api_reject(*q, FILTER_CLOSE);
	else
		filter_api_accept(*q);

	free(q);
}

static int
dnsbl_on_connect(uint64_t id, struct filter_connect *conn)
{
	struct addrinfo		 hints;
	struct sockaddr_in	*sain;
	in_addr_t		 in_addr;
	struct asr_query	*aq;
	uint64_t		*q;
	char			 buf[512];

	if (conn->remote.ss_family != AF_INET)
		return filter_api_accept(id);
	
	in_addr = ((const struct sockaddr_in *)&conn->remote)->sin_addr.s_addr;

	in_addr = ntohl(in_addr);
	if (snprintf(buf, sizeof(buf), "%d.%d.%d.%d.%s.",
	    in_addr & 0xff,
	    (in_addr >> 8) & 0xff,
	    (in_addr >> 16) & 0xff,
	    (in_addr >> 24) & 0xff,
	    dnsbl_host) >= sizeof(buf)) {
		log_warnx("filter-dnsbl: host name too long: %s", buf);
		return filter_api_reject(id, FILTER_FAIL);
	}

	q = calloc(1, sizeof *q);
	if (q == NULL) {
		log_warn("filter-dnsbl: calloc");
		return filter_api_reject(id, FILTER_FAIL);
	}
	*q = id;

	memset(&hints, 0, sizeof (hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	aq = getaddrinfo_async(buf, NULL, &hints, NULL);
	if (aq == NULL) {
		log_warn("filter-dnsbl: getaddrinfo_async");
		free(q);
		return filter_api_reject(id, FILTER_FAIL);
	}

	log_debug("debug: filter-dnsbl: checking %s", buf);

	event_asr_run(aq, dnsbl_event_dispatch, q);

	return (1);
}

int
main(int argc, char **argv)
{
	int	ch;

	log_init(-1);

	while ((ch = getopt(argc, argv, "h:")) != -1) {
		switch (ch) {
		case 'h':
			dnsbl_host = optarg;
			break;
		default:
			log_warnx("warn: filter-dnsbl: bad option");
			return (1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	log_debug("debug: filter-dnsbl: starting...");

	filter_api_on_connect(dnsbl_on_connect);
	filter_api_loop();

	log_debug("debug: filter-dnsbl: exiting");

	return (1);
}
