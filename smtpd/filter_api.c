/*	$OpenBSD: filter_api.c,v 1.4 2012/08/19 14:16:58 chl Exp $	*/

/*
 * Copyright (c) 2011 Gilles Chehade <gilles@openbsd.org>
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
#include <sys/uio.h>

#include <err.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd-api.h"

static struct tree		queries;

struct query {
	uint64_t		qid;
	enum filter_hook	hook;
};
static int			register_done;

static struct filter_internals {
	uint32_t	hooks;
	uint32_t	flags;

	struct event	ev;
	struct imsgbuf	ibuf;
} fi;

static void filter_api_init(void);
static void filter_register_callback(enum filter_hook, void *, void *);
static void filter_response(uint64_t, int, int, const char *line, int);
static void filter_event_add(void);
static void filter_dispatch(int, short, void *);
static void filter_dispatch_event(uint64_t, enum filter_hook);
static void filter_dispatch_dataline(uint64_t, const char *);
static void filter_dispatch_data(uint64_t, uint64_t);
static void filter_dispatch_eom(uint64_t, uint64_t);
static void filter_dispatch_notify(uint64_t, enum filter_status);
static void filter_dispatch_connect(uint64_t, uint64_t, struct filter_connect *);
static void filter_dispatch_helo(uint64_t, uint64_t, const char *);
static void filter_dispatch_mail(uint64_t, uint64_t, struct filter_mailaddr *);
static void filter_dispatch_rcpt(uint64_t, uint64_t, struct filter_mailaddr *);

void
filter_api_loop(void)
{
	if (register_done) {
		errx(1, "filter_api_loop already called");
		return;
	}

	filter_api_init();

	register_done = 1;

	filter_event_add();
	if (event_dispatch() < 0)
		errx(1, "event_dispatch");
}

void
filter_api_accept(uint64_t id)
{
	filter_response(id, FILTER_OK, 0, NULL, 0);
}

void
filter_api_accept_notify(uint64_t id)
{
	filter_response(id, FILTER_OK, 0, NULL, 1);
}

void
filter_api_reject(uint64_t id, enum filter_status status)
{
	/* This is NOT an acceptable status for a failure */
	if (status == FILTER_OK)
		status = FILTER_FAIL;

	filter_response(id, status, 0, NULL, 0);
}

void
filter_api_reject_code(uint64_t id, enum filter_status status, uint32_t code,
    const char *line)
{
	/* This is NOT an acceptable status for a failure */
	if (status == FILTER_OK)
		status = FILTER_FAIL;

	filter_response(id, status, code, line, 0);
}

void
filter_api_data(uint64_t id, const char *line)
{
	struct filter_data_msg	 msg;

	msg.id = id;
	strlcpy(msg.line, line, sizeof(line));

	imsg_compose(&fi.ibuf, IMSG_FILTER_DATA, 0, 0, -1, &msg, sizeof(msg));

	filter_event_add();
}

static void
filter_response(uint64_t qid, int status, int code, const char *line, int notify)
{
	struct filter_response_msg	 r;
	struct filter_query		*q;

	q = tree_xpop(&queries, qid);
	free(q);

	r.qid = qid;
	r.status = status;
	r.code = code;
	r.notify = notify;
	if (line == NULL)
		line = "";
	strlcpy(r.response, line, sizeof(r.response));

	imsg_compose(&fi.ibuf, IMSG_FILTER_RESPONSE, 0, 0, -1, &r, sizeof(r));

	filter_event_add();
}

static void
filter_api_init(void)
{
	static int	init = 0;

	if (init)
		return;

	init = 1;

	bzero(&fi, sizeof(fi));
	tree_init(&queries);
	imsg_init(&fi.ibuf, 0);
	event_init();

	fi.hooks = -1;
}

static void
filter_register_callback(enum filter_hook hook, void *cb, void *cb_arg)
{
	if (register_done)
		errx(1, "filter_register_callback: called at runtime");

	filter_api_init();

	switch (hook) {
	case HOOK_CONNECT:
	case HOOK_DISCONNECT:
	case HOOK_HELO:
	case HOOK_MAIL:
	case HOOK_RCPT:
	case HOOK_DATA:
	case HOOK_DATALINE:
	case HOOK_COMMIT:
	case HOOK_RESET:
	default:
		errx(1, "filter_register_callback: unknown filter hook");
	}
	fi.hooks |= hook;
}

static void
filter_event_add(void)
{
	short	evflags;
	
	evflags = EV_READ;
	if (fi.ibuf.w.queued)
		evflags |= EV_WRITE;

	event_del(&fi.ev);
	event_set(&fi.ev, 0, evflags, filter_dispatch, NULL);
	event_add(&fi.ev, NULL);
}

static void
filter_dispatch(int fd, short event, void *p)
{
	struct imsg			 imsg;
	ssize_t				 n;
	struct session			*session;
	uint32_t			 v;
	struct filter_register_msg	 reg;
	struct filter_query_msg		*query;
	struct filter_event_msg		*evt;
	struct filter_data_msg		*data;
	struct filter_notify_msg	*notify;

	if (event & EV_READ) {
		n = imsg_read(&fi.ibuf);
		if (n == -1)
			err(1, "imsg_read");
		if (n == 0) {
			event_del(&fi.ev);
			event_loopexit(NULL);
			return;
		}
	}

	if (event & EV_WRITE) {
		if (msgbuf_write(&fi.ibuf.w) == -1)
			err(1, "msgbuf_write");
	}

	for (;;) {
		n = imsg_get(&fi.ibuf, &imsg);
		if (n == -1)
			errx(1, "imsg_get");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_FILTER_REGISTER:
			v = *(uint32_t *)imsg.data;
			if (v != FILTER_API_VERSION)
				errx(1, "API version mismatch");

			reg.hooks = fi.hooks;
			reg.flags = fi.flags;	
			imsg_compose(&fi.ibuf, IMSG_FILTER_REGISTER, 0, 0, -1,
			    &reg, sizeof(reg));
			break;

		case IMSG_FILTER_EVENT:
			evt = imsg.data;
			filter_dispatch_event(evt->id, evt->event);
			break;

		case IMSG_FILTER_QUERY:
			query = imsg.data;
			/* XXX ? */
			tree_xset(&queries, query->qid, NULL);
			switch(query->hook) {
			case HOOK_CONNECT:
				filter_dispatch_connect(query->id, query->qid,
				    &query->u.connect);
				break;
			case HOOK_HELO:
				filter_dispatch_helo(query->id, query->qid,
				    query->u.line.line);
				break;
			case HOOK_MAIL:
				filter_dispatch_mail(query->id, query->qid,
				    &query->u.maddr);
				break;
			case HOOK_RCPT:
				filter_dispatch_rcpt(query->id, query->qid,
				    &query->u.maddr);
				break;
			case HOOK_DATA:
				filter_dispatch_data(query->id, query->qid);
				break;
			case HOOK_ENDOFDATA:
				filter_dispatch_eom(query->id, query->qid);
				break;
			default:
				errx(1, "bad query hook", query->hook);
			}
			break;

		case IMSG_FILTER_NOTIFY:
			notify = imsg.data;
			filter_dispatch_notify(notify->qid, notify->status);
			break;

		case IMSG_FILTER_DATA:
			data = imsg.data;
			filter_dispatch_dataline(data->id, data->line);
			break;
		}

		imsg_free(&imsg);
	}

	filter_event_add();
}

static void
filter_dispatch_event(uint64_t id,  enum filter_hook event)
{
	printf("filter-event: id=%016"PRIx64", event=%i\n",
	    id, event);
}

static void
filter_dispatch_notify(uint64_t qid, enum filter_status status)
{
	printf("filter-notify: qid=%016"PRIx64", status=%i\n",
	    qid, status);
}

static void
filter_dispatch_connect(uint64_t id, uint64_t qid, struct filter_connect *conn)
{
	printf("filter-connect: id=%016"PRIx64", qid=%016"PRIx64" hostname=%s\n",
	    id, qid, conn->hostname);
	filter_api_accept(qid);
}

static void
filter_dispatch_helo(uint64_t id, uint64_t qid, const char *helo)
{
	printf("filter: HELO id=%016"PRIx64", qid=%016"PRIx64" %s\n",
	    id, qid, helo);
	filter_api_accept(qid);
}

static void
filter_dispatch_mail(uint64_t id, uint64_t qid, struct filter_mailaddr *mail)
{
	printf("filter: MAIL id=%016"PRIx64", qid=%016"PRIx64" %s@%s\n",
	    id, qid, mail->user, mail->domain);
	filter_api_accept(qid);
}

static void
filter_dispatch_rcpt(uint64_t id, uint64_t qid, struct filter_mailaddr *rcpt)
{
	printf("filter: RCPT id=%016"PRIx64", qid=%016"PRIx64" %s@%s\n",
	    id, qid, rcpt->user, rcpt->domain);
	filter_api_accept(qid);
}

static void
filter_dispatch_data(uint64_t id, uint64_t qid)
{
	printf("filter: DATA id=%016"PRIx64", qid=%016"PRIx64"\n", id, qid);
	filter_api_accept(qid);
}

static void
filter_dispatch_dataline(uint64_t id, const char *data)
{
	printf("filter-data: id=%016"PRIx64", \"%s\"\n", id, data);
	/* filter_api_data(id, data); */
}

static void
filter_dispatch_eom(uint64_t id, uint64_t qid)
{
	printf("filter-eom: id=%016"PRIx64", qid=%016"PRIx64"\n", id, qid);
	filter_api_accept(qid);
}
