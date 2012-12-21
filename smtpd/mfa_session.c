/*	$OpenBSD: mfa_session.c,v 1.11 2012/10/11 21:51:37 gilles Exp $	*/

/*
 * Copyright (c) 2011 Gilles Chehade <gilles@openbsd.org>
 * Copyright (c) 2012 Eric Faurot <eric@openbsd.org>
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
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <resolv.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd.h"
#include "log.h"

enum {
	QT_QUERY,
	QT_EVENT,
};

enum {
	QUERY_READY,
	QUERY_WAITING,
	QUERY_RUNNING,
	QUERY_DONE
};

struct mfa_filter {
	TAILQ_ENTRY(mfa_filter)		 entry;
	struct mproc			 mproc;
	int				 hooks;
	int				 flags;
	int				 ready;
};

struct mfa_filter_chain {
	TAILQ_HEAD(, mfa_filter)	filters;
};

struct mfa_session {
	uint64_t				id;
	int					terminate;
	TAILQ_HEAD(mfa_queries, mfa_query)	queries;
};

struct mfa_query {
	uint64_t		 qid;
	int			 type;
	int			 hook;
	struct mfa_session	*session;
	TAILQ_ENTRY(mfa_query)	 entry;

	int			 state;
	int			 hasrun;
	struct mfa_filter	*current;
	struct tree		 notify;  /* list of filters to notify */

	/* current data */
	union {
		struct filter_connect	connect;
		struct filter_line	line;
		struct filter_mailaddr	maddr;
	} u;

	/* current response */
	struct {
		int	 status;
		int	 code;
		char	*response;	
	} smtp;
};

static void mfa_filter_imsg(struct mproc *, struct imsg *);
static struct mfa_query *mfa_query(struct mfa_session *, int, int);
static void mfa_drain_query(struct mfa_query *);
static void mfa_run_query(struct mfa_filter *, struct mfa_query *);
static void mfa_run_data(struct mfa_filter *, uint64_t, const char *);
static struct mfa_filter_chain	chain;

static const char * type_to_str(int);
static const char * hook_to_str(int);
static const char * status_to_str(int);

struct tree	sessions;
struct tree	queries;

void
mfa_filter_init(void)
{
	static int		 init = 0;
	struct filter		*filter;
	void			*iter;
	struct mfa_filter	*f;
	struct mproc		*p;
	int			 r;
	uint32_t		 v = FILTER_API_VERSION;

	if (init)
		return;
	init = 1;

	tree_init(&sessions);
	tree_init(&queries);

	TAILQ_INIT(&chain.filters);

	iter = NULL;
	while (dict_iter(&env->sc_filters, &iter, NULL, (void **)&filter)) {
		f = xcalloc(1, sizeof *f, "mfa_filter_init");
		p = &f->mproc;
		p->handler = mfa_filter_imsg;
		p->proc = -1;
		p->name = xstrdup(filter->name, "mfa_filter_init");
		p->data = f;
		r = mproc_fork(p, filter->path, filter->name);
		m_compose(p, IMSG_FILTER_REGISTER, 0, 0, -1, &v, sizeof(v));
		mproc_enable(p);
		TAILQ_INSERT_TAIL(&chain.filters, f, entry);
	}

	if (TAILQ_FIRST(&chain.filters) == NULL)
		mfa_ready();
}

void
mfa_filter_connect(uint64_t id, const struct sockaddr *local,
	const struct sockaddr *remote, const char *host)
{
	struct mfa_session	*s;
	struct mfa_query	*q;

	s = xcalloc(1, sizeof(*s), "mfa_query_connect");
	s->id = id;
	TAILQ_INIT(&s->queries);
	tree_xset(&sessions, s->id, s);

	q = mfa_query(s, QT_QUERY, HOOK_CONNECT);

	memmove(&q->u.connect.local, local, local->sa_len);
	memmove(&q->u.connect.remote, remote, remote->sa_len);
	strlcpy(q->u.connect.hostname, host, sizeof(q->u.connect.hostname));

	q->smtp.status = MFA_OK;
	q->smtp.code = 0;
	q->smtp.response = NULL;

	mfa_drain_query(q);
}

void
mfa_filter_event(uint64_t id, int hook)
{
	struct mfa_session	*s;
	struct mfa_query	*q;

	/* On disconnect, the session is virtualy dead */
	if (hook == HOOK_DISCONNECT)
		s = tree_xpop(&sessions, id);
	else
		s = tree_xget(&sessions, id);
	q = mfa_query(s, QT_EVENT, hook);

	mfa_drain_query(q);
}

void
mfa_filter_mailaddr(uint64_t id, int hook, const struct mailaddr *maddr)
{
	struct mfa_session	*s;
	struct mfa_query	*q;

	s = tree_xget(&sessions, id);
	q = mfa_query(s, QT_QUERY, hook);

	strlcpy(q->u.maddr.user, maddr->user, sizeof(q->u.maddr.user));
	strlcpy(q->u.maddr.domain, maddr->domain, sizeof(q->u.maddr.domain));

	mfa_drain_query(q);
}

void
mfa_filter_line(uint64_t id, int hook, const char *line)
{
	struct mfa_session	*s;
	struct mfa_query	*q;

	s = tree_xget(&sessions, id);
	q = mfa_query(s, QT_QUERY, hook);

	strlcpy(q->u.line.line, line, sizeof(q->u.line.line));

	mfa_drain_query(q);
}

void
mfa_filter(uint64_t id, int hook)
{
	struct mfa_session	*s;
	struct mfa_query	*q;

	s = tree_xget(&sessions, id);
	q = mfa_query(s, QT_QUERY, hook);

	mfa_drain_query(q);
}

void
mfa_filter_data(uint64_t id, const char *line)
{
	mfa_run_data(TAILQ_FIRST(&chain.filters), id, line);
}

static void
mfa_run_data(struct mfa_filter *f, uint64_t id, const char *line)
{
	struct mfa_data_msg	 resp;
	struct mproc		*p;
	size_t			 len;

	log_trace(TRACE_MFA,
	    "mfa: running data for %016"PRIx64" on filter %p: %s", id, f, line);

	p = p_smtp;
	len = sizeof(id) + strlen(line) + 1;

	/* Send the dataline to the filters that want to see it. */
	while (f) {
		if (f->hooks & HOOK_DATALINE) {
			p = &f->mproc;
			m_create(p, IMSG_FILTER_DATA, 0, 0, -1, len);
			m_add(p, &id, sizeof(id));
			m_add(p, line, len - sizeof(id));
			m_close(p);

			/*
			 * If this filter wants to alter data, we stop
			 * iterating here, and the filter becomes responsible
			 * for sending datalines back.
			 */
			if (f->flags & FILTER_ALTERDATA)
				return;
		}
		f = TAILQ_NEXT(f, entry);
	}

	/* When all filters are done, send the line back to the smtp process. */
	resp.reqid = id;
	strlcpy(resp.buffer, line, sizeof(resp.buffer));
	m_compose(p, IMSG_MFA_SMTP_DATA, 0, 0, -1, &resp, sizeof(resp));
}

static struct mfa_query *
mfa_query(struct mfa_session *s, int type, int hook)
{
	struct mfa_query	*q;

	q = xcalloc(1, sizeof *q, "mfa_query");
	q->qid = generate_uid();
	q->session = s;
	q->type = type;
	q->hook = hook;
	tree_init(&q->notify);
	TAILQ_INSERT_TAIL(&s->queries, q, entry);

	q->state = QUERY_READY;
	q->current = TAILQ_FIRST(&chain.filters);
	q->hasrun = 0;

	log_trace(TRACE_MFA, "mfa: new query %s %s", type_to_str(type),
	    hook_to_str(hook));

	return (q);
}

static void
mfa_drain_query(struct mfa_query *q)
{
	struct mfa_filter		*f;
	struct mfa_query		*prev;
	struct mfa_smtp_resp_msg	 resp;
	struct filter_notify_msg	 notify;

	/*
	 * The query must be passed through all filters that registered
	 * a hook, until one rejects it.  
	 */
	while (q->state != QUERY_DONE) {

		/* Walk over all filters */
		while (q->current) {

			/* Trigger the current filter if not done yet. */
			if (!q->hasrun) {
				mfa_run_query(q->current, q);
				q->hasrun = 1;
			}
			if (q->state == QUERY_RUNNING)
				return;

			/*
			 * Do not move forward if the query ahead of us is
			 * waiting on this filter.
			 */
			prev = TAILQ_PREV(q, mfa_queries, entry);
			if (prev && prev->current == q->current) {
				q->state = QUERY_WAITING;
				return;
			}

			q->current = TAILQ_NEXT(q->current, entry);
			q->hasrun = 0;
		}
		q->state = QUERY_DONE;
	}

	if (q->type == QT_QUERY) {

		log_trace(TRACE_MFA,
		    "mfa: query 0x%016"PRIx64" done: "
		    "status=%s code=%i response=\"%s\"",
		    q->qid,
		    status_to_str(q->smtp.status),
		    q->smtp.code,
		    q->smtp.response);

		/* Done, notify all listeners and return smtp response */
		notify.qid = q->qid;
		notify.status = q->smtp.status;
		while (tree_poproot(&q->notify, NULL, (void**)&f))
			m_compose(&f->mproc, IMSG_FILTER_NOTIFY, 0, 0, -1,
			    &notify, sizeof (notify));

		resp.reqid = q->session->id;
		resp.status = q->smtp.status;
		resp.code = q->smtp.code;
		if (q->smtp.response)
			strlcpy(resp.line, q->smtp.response, sizeof resp.line);
		else
			resp.line[0] = '\0';
		m_compose(p_smtp, IMSG_MFA_SMTP_RESPONSE, 0, 0, -1, &resp,
		    sizeof(resp));

		free(q->smtp.response);
	}

	/* If the query was a disconnect event, the session can be freed */
	if (q->type == HOOK_DISCONNECT) {
		/* XXX assert prev == NULL */
		free(q->session);
	}

	log_trace(TRACE_MFA, "mfa: freeing query 0x%016" PRIx64, q->qid);

	TAILQ_REMOVE(&q->session->queries, q, entry);
	free(q);
}

static void
mfa_run_query(struct mfa_filter *f, struct mfa_query *q)
{
/*
	m_compose(&f->mproc, q->type, 0, 0, -1, q->data, q->datalen);
*/
	if (q->type == QT_QUERY) {
		tree_xset(&queries, q->qid, q);
		q->state = QUERY_RUNNING;
	}

}

static void
mfa_filter_imsg(struct mproc *p, struct imsg *imsg)
{
	struct filter_register_msg	*reg;
	struct filter_data_msg		*data;
	struct filter_response_msg	*resp;
	struct mfa_filter		*f;
	struct mfa_query		*q, *next;

	f = p->data;

	switch (imsg->hdr.type) {

	case IMSG_FILTER_REGISTER:
		if (f->ready) {
			log_warnx("warn: filter \"%s\" already registered",
			    f->mproc.name);
			exit(1);
		}
		reg = imsg->data;
		f->hooks = reg->hooks;
		f->flags = reg->flags;
		f->ready = 1;

		log_debug("debug: filter \"%s\": hooks 0x%08x flags 0x%04x",
		    f->mproc.name, f->hooks, f->flags);

		TAILQ_FOREACH(f, &chain.filters, entry)
			if (!f->ready)
				return;
		mfa_ready();
		break;

	case IMSG_FILTER_DATA:
		data = imsg->data;
		mfa_run_data(TAILQ_NEXT(f, entry), data->id, data->line);
		break;

	case IMSG_FILTER_RESPONSE:
		resp = imsg->data;

		q = tree_xpop(&queries, resp->qid);
		q->smtp.status = resp->status;
		if (resp->code)
			q->smtp.code = resp->code;
		if (resp->response[0]) {
			free(q->smtp.response);
			q->smtp.response = xstrdup(resp->response,
			    "mfa_filter_imsg");
		}
		q->state = (resp->status == MFA_OK) ? QUERY_READY : QUERY_DONE;

		next = TAILQ_NEXT(q, entry);
		mfa_drain_query(q);

		/*
		 * If there is another query after this one which is waiting,
		 * make it move forward.
		 */
		if (next && next->state == QUERY_WAITING)
			mfa_drain_query(next);
		break;

	default:
		log_warnx("bad imsg from filter %s", p->name);
		exit(1);
	}
}

#define CASE(x) case x : return #x

static const char *
hook_to_str(int hook)
{
	switch (hook) {
	CASE(HOOK_CONNECT);
	CASE(HOOK_HELO);
	CASE(HOOK_MAIL);
	CASE(HOOK_RCPT);
	CASE(HOOK_DATA);
	CASE(HOOK_ENDOFDATA);
	CASE(HOOK_RESET);
	CASE(HOOK_DISCONNECT);
	CASE(HOOK_COMMIT);
	CASE(HOOK_ROLLBACK);
	CASE(HOOK_DATALINE);
	default:
		return "HOOK_???";
	}
}

static const char *
type_to_str(int type)
{
	switch (type) {
	CASE(QT_QUERY);
	CASE(QT_EVENT);
	default:
		return "QT_???";
	}
}

static const char *
status_to_str(int status)
{
	switch (status) {
	CASE(MFA_OK);
	CASE(MFA_FAIL);
	CASE(MFA_CLOSE);
	default:
		return "MFA_???";
	}
}
