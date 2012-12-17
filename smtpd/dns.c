/*	$OpenBSD: dns.c,v 1.61 2012/11/12 14:58:53 eric Exp $	*/

/*
 * Copyright (c) 2008 Gilles Chehade <gilles@openbsd.org>
 * Copyright (c) 2009 Jacek Masiulaniec <jacekm@dobremiasto.net>
 * Copyright (c) 2011-2012 Eric Faurot <eric@faurot.net>
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
#include <sys/socket.h>
#include "sys-tree.h"
#include "sys-queue.h"
#include <sys/uio.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <event.h>
#include <netdb.h>
#include <resolv.h>
#include "imsg.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asr.h"
#include "asr_private.h"
#include "smtpd.h"
#include "log.h"

struct dns_lookup {
	struct dns_session	*session;
	int			 preference;
};

struct dns_session {
	struct mproc		*p;
	uint64_t		 reqid;
	int			 type;
	char			 name[MAXHOSTNAMELEN];
	size_t			 mxfound;
	int			 error;
	int			 refcount;
};

struct async_event;
struct async_event * async_run_event(struct async *,
	void (*)(int, struct async_res *, void *), void *);

static void dns_lookup_host(struct dns_session *, const char *, int);
static void dns_dispatch_host(int, struct async_res *, void *);
static void dns_dispatch_ptr(int, struct async_res *, void *);
static void dns_dispatch_mx(int, struct async_res *, void *);
static void dns_dispatch_mx_preference(int, struct async_res *, void *);

#define print_dname(a,b,c) asr_strdname(a, b, c)

void
dns_query_host(uint64_t id, const char *host)
{
	struct dns_req_msg	req;

	req.reqid = id;
	strlcpy(req.u.host, host, sizeof(req.u.host));
	m_compose(p_lka, IMSG_DNS_HOST, 0, 0, -1, &req, sizeof(req));
}

void
dns_query_ptr(uint64_t id, const struct sockaddr *sa)
{
	struct dns_req_msg	req;

	req.reqid = id;
	memmove(&req.u.ss, sa, SA_LEN(sa));
	m_compose(p_lka, IMSG_DNS_PTR, 0, 0, -1, &req, sizeof(req));
}

void
dns_query_mx(uint64_t id, const char *domain)
{
	struct dns_req_msg	req;

	req.reqid = id;
	strlcpy(req.u.domain, domain, sizeof(req.u.domain));
	m_compose(p_lka, IMSG_DNS_MX, 0, 0, -1, &req, sizeof(req));
}

void
dns_query_mx_preference(uint64_t id, const char *domain, const char *mx)
{
	struct dns_req_msg	req;

	req.reqid = id;
	strlcpy(req.u.mxpref.domain, domain, sizeof(req.u.mxpref.domain));
	strlcpy(req.u.mxpref.mx, mx, sizeof(req.u.mxpref.mx));
	m_compose(p_lka, IMSG_DNS_MX_PREFERENCE, 0, 0, -1, &req, sizeof(req));
}

void
dns_imsg(struct mproc *p, struct imsg *imsg)
{
	struct dns_req_msg	*req;
	struct async		*as;
	struct sockaddr		*sa;
	struct dns_session	*s;

	req = imsg->data;
	s = xcalloc(1, sizeof *s, "dns_imsg");
	s->p = p;
	s->reqid = req->reqid;
	s->type = imsg->hdr.type;

	switch (s->type) {

	case IMSG_DNS_HOST:
		dns_lookup_host(s, req->u.host, -1);
		return;

	case IMSG_DNS_PTR:
		sa = (struct sockaddr*)&req->u.ss;
		as = getnameinfo_async(sa, SA_LEN(sa), s->name, sizeof(s->name),
		    NULL, 0, 0, NULL);
		async_run_event(as, dns_dispatch_ptr, s);
		return;

	case IMSG_DNS_MX:
		strlcpy(s->name, req->u.domain, sizeof(s->name));
		as = res_query_async(s->name, C_IN, T_MX, NULL, 0, NULL);
		async_run_event(as, dns_dispatch_mx, s);
		return;

	case IMSG_DNS_MX_PREFERENCE:
		strlcpy(s->name, req->u.mxpref.mx, sizeof(s->name));
		as = res_query_async(req->u.mxpref.domain, C_IN, T_MX, NULL, 0,
		    NULL);
		async_run_event(as, dns_dispatch_mx_preference, s);
		return;

	default:
		log_warnx("warn: bad dns request %i", s->type);
		fatal(NULL);
	}
}

static void
dns_dispatch_host(int ev, struct async_res *ar, void *arg)
{
	struct dns_resp_msg	 resp;
	struct dns_session	*s;
	struct dns_lookup	*lookup = arg;
	struct addrinfo		*ai;

	s = lookup->session;
	resp.reqid = s->reqid;
	resp.error = DNS_OK;

	for (ai = ar->ar_addrinfo; ai; ai = ai->ai_next) {
		resp.u.host.preference = lookup->preference;
		memmove(&resp.u.host.ss, ai->ai_addr, ai->ai_addrlen);
		m_compose(s->p, IMSG_DNS_HOST, 0, 0, -1, &resp, sizeof(resp));
		s->mxfound++;
	}
	free(lookup);
	if (ar->ar_addrinfo)
		asr_freeaddrinfo(ar->ar_addrinfo);

	if (ar->ar_gai_errno)
		s->error = ar->ar_gai_errno;

	if (--s->refcount)
		return;

	if (s->mxfound == 0)
		resp.error = DNS_ENOTFOUND;

	m_compose(s->p, IMSG_DNS_HOST_END, 0, 0, -1, &resp, sizeof(resp));
	free(s);
}

static void
dns_dispatch_ptr(int ev, struct async_res *ar, void *arg)
{
	struct dns_session	*s = arg;
	struct dns_resp_msg	 resp;

	/* The error code could be more precise, but we don't currently care */
	resp.reqid = s->reqid;
	resp.error = ar->ar_gai_errno ? DNS_ENOTFOUND : DNS_OK;
	strlcpy(resp.u.ptr, s->name, sizeof resp.u.ptr);
	m_compose(s->p, IMSG_DNS_PTR, 0, 0, -1, &resp, sizeof(resp));
	free(s);
}

static void
dns_dispatch_mx(int ev, struct async_res *ar, void *arg)
{
	struct dns_session	*s = arg;
	struct dns_resp_msg	 resp;
	struct unpack		 pack;
	struct header		 h;
	struct query		 q;
	struct rr		 rr;
	char			 buf[512];
	size_t			 found;

	if (ar->ar_h_errno && ar->ar_h_errno != NO_DATA) {
		resp.reqid = s->reqid;
		if (ar->ar_rcode == NXDOMAIN)
			resp.error = DNS_ENONAME;
		else if (ar->ar_h_errno == NO_RECOVERY)
			resp.error = DNS_EINVAL;
		else
			resp.error = DNS_RETRY;
		m_compose(s->p, IMSG_DNS_HOST_END, 0, 0, -1, &resp,
		    sizeof(resp));
		free(s);
		free(ar->ar_data);
		return;
	}

	unpack_init(&pack, ar->ar_data, ar->ar_datalen);
	unpack_header(&pack, &h);
	unpack_query(&pack, &q);

	found = 0;
	for (; h.ancount; h.ancount--) {
		unpack_rr(&pack, &rr);
		if (rr.rr_type != T_MX)
			continue;
		print_dname(rr.rr.mx.exchange, buf, sizeof(buf));
		buf[strlen(buf) - 1] = '\0';
		dns_lookup_host(s, buf, rr.rr.mx.preference);
		found++;
	}
	free(ar->ar_data);

	/* fallback to host if no MX is found. */
	if (found == 0)
		dns_lookup_host(s, s->name, 0);
}

static void
dns_dispatch_mx_preference(int ev, struct async_res *ar, void *arg)
{
	struct dns_session	*s = arg;
	struct dns_resp_msg	 resp;
	struct unpack		 pack;
	struct header		 h;
	struct query		 q;
	struct rr		 rr;
	char			 buf[512];

	resp.reqid = s->reqid;

	if (ar->ar_h_errno) {
		if (ar->ar_rcode == NXDOMAIN)
			resp.error = DNS_ENONAME;
		else if (ar->ar_h_errno == NO_RECOVERY
		    || ar->ar_h_errno == NO_DATA)
			resp.error = DNS_EINVAL;
		else
			resp.error = DNS_RETRY;
	}
	else {
		resp.error = DNS_ENOTFOUND;
		unpack_init(&pack, ar->ar_data, ar->ar_datalen);
		unpack_header(&pack, &h);
		unpack_query(&pack, &q);
		for (; h.ancount; h.ancount--) {
			unpack_rr(&pack, &rr);
			if (rr.rr_type != T_MX)
				continue;
			print_dname(rr.rr.mx.exchange, buf, sizeof(buf));
			buf[strlen(buf) - 1] = '\0';
			if (!strcasecmp(s->name, buf)) {
				resp.error = DNS_OK;
				resp.u.preference = rr.rr.mx.preference;
				break;
			}
		}
	}

	free(ar->ar_data);

	m_compose(s->p, IMSG_DNS_MX_PREFERENCE, 0, 0, -1, &resp, sizeof(resp));
	free(s);
}

static void
dns_lookup_host(struct dns_session *s, const char *host, int preference)
{
	struct dns_lookup	*lookup;
	struct addrinfo		 hints;
	struct async		*as;

	lookup = xcalloc(1, sizeof *lookup, "dns_lookup_host");
	lookup->preference = preference;
	lookup->session = s;
	s->refcount++;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	as = getaddrinfo_async(host, NULL, &hints, NULL);
	async_run_event(as, dns_dispatch_host, lookup);
}

/* Generic libevent glue for asr */

struct async_event {
	struct async	*async;
	struct event	 ev;
	void		(*callback)(int, struct async_res *, void *);
	void		*arg;
};

static void async_event_dispatch(int, short, void *);

struct async_event *
async_run_event(struct async * async,
    void (*cb)(int, struct async_res *, void *), void *arg)
{
	struct async_event	*aev;
	struct timeval		 tv;

	aev = calloc(1, sizeof *aev);
	if (aev == NULL)
		return (NULL);
	aev->async = async;
	aev->callback = cb;
	aev->arg = arg;
	tv.tv_sec = 0;
	tv.tv_usec = 1;
	evtimer_set(&aev->ev, async_event_dispatch, aev);
	evtimer_add(&aev->ev, &tv);
	return (aev);
}

static void
async_event_dispatch(int fd, short ev, void *arg)
{
	struct async_event	*aev = arg;
	struct async_res	 ar;
	int			 r;
	struct timeval		 tv;

	while ((r = async_run(aev->async, &ar)) == ASYNC_YIELD)
		aev->callback(r, &ar, aev->arg);

	event_del(&aev->ev);
	if (r == ASYNC_COND) {
		event_set(&aev->ev, ar.ar_fd,
			  ar.ar_cond == ASYNC_READ ? EV_READ : EV_WRITE,
			  async_event_dispatch, aev);
		tv.tv_sec = ar.ar_timeout / 1000;
		tv.tv_usec = (ar.ar_timeout % 1000) * 1000;
		event_add(&aev->ev, &tv);
	} else { /* ASYNC_DONE */
		aev->callback(r, &ar, aev->arg);
		free(aev);
	}
}
