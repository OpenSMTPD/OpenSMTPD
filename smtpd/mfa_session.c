/*	$OpenBSD: mfa_session.c,v 1.11 2012/10/11 21:51:37 gilles Exp $	*/

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

static void mfa_session_proceed(struct mfa_session *);
static void mfa_session_destroy(struct mfa_session *);
static void mfa_session_done(struct mfa_session *);
static void mfa_session_fail(struct mfa_session *, enum filter_status, uint32_t, char *);

static void mfa_session_filter_register(uint32_t, struct filter *);
void mfa_session_imsg_handler(struct imsg *, void *);

static struct tree	sessions;

struct fhook {
	SIMPLEQ_ENTRY(fhook)	entry;
	struct filter	       *filter;
};

/* XXX - needs to be update to match the number of filter_hook in smtpd-api.h */
SIMPLEQ_HEAD(flist, fhook)	filter_hooks[9];

void
mfa_session_filters_init(void)
{
	struct filter  *filter;
	void	       *iter;
	size_t		i;
	uint32_t	version = FILTER_API_VERSION;

	dict_init(&sessions);

	for (i = 0; i < nitems(filter_hooks); ++i)
		SIMPLEQ_INIT(&filter_hooks[i]);

	iter = NULL;
	while (dict_iter(&env->sc_filters, &iter, NULL, (void **)&filter)) {
		filter->process = imsgproc_fork(filter->path, filter->name,
		    mfa_session_imsg_handler, filter);
		if (filter->process == NULL)
			fatalx("could not start filter");
		imsg_compose(filter->process->ibuf, HOOK_REGISTER, 0, 0, -1,
		    &version, sizeof version);
		imsgproc_set_write(filter->process);
	}
}

static void
mfa_session_filter_register(uint32_t filtermask, struct filter *filter)
{
	struct fhook   *np;
	size_t		i;

	for (i = 0; i < nitems(filter_hooks); ++i) {
		if ((1 << i) & filtermask) {
			np = xcalloc(1, sizeof *np, "mfa_session_filter_register");
			np->filter = filter;
			SIMPLEQ_INSERT_TAIL(&filter_hooks[i], np, entry);
			env->filtermask |= filtermask;
		}
	}
	imsg_compose_event(env->sc_ievs[PROC_SMTP], HOOK_REGISTER, 0, 0,
	    -1, &env->filtermask, sizeof(env->filtermask));
}

void
mfa_session(uint64_t id, enum filter_hook hook, union mfa_session_data *data)
{
	struct mfa_session     *ms;

	ms = xcalloc(1, sizeof(*ms), "mfa_session");
	ms->id      = id;
	ms->hook    = hook;
	ms->data    = *data;
	tree_xset(&sessions, ms->id, ms);

	/* no filter handling this hook */
	if (!(hook & env->filtermask)) {
		mfa_session_done(ms);
		return;
	}

	ms->fhook = SIMPLEQ_FIRST(&filter_hooks[ffs(ms->hook) - 1]);
	mfa_session_proceed(ms);
}

static void
mfa_session_proceed(struct mfa_session *ms)
{
	struct filter_msg	fm;
	struct filter	       *filter = ((struct fhook *)ms->fhook)->filter;

	bzero(&fm, sizeof fm);
	fm.id = ms->id;

	switch (ms->hook) {
	case HOOK_CONNECT:
		if (strlcpy(fm.u.connect.hostname, ms->data.evp.hostname,
			sizeof(fm.u.connect.hostname))
		    >= sizeof(fm.u.connect.hostname))
			fatalx("mfa_session_proceed: CONNECT: truncation");
		fm.u.connect.hostaddr = ms->data.evp.ss;
		break;

	case HOOK_HELO:
		if (strlcpy(fm.u.helo.host, ms->data.evp.helo,
			sizeof(fm.u.helo.host))
		    >= sizeof(fm.u.helo.host))
			fatalx("mfa_session_proceed: HELO: truncation");
		break;

	case HOOK_MAIL:
		if (strlcpy(fm.u.mail.user, ms->data.evp.sender.user,
			sizeof(fm.u.mail.user)) >= sizeof(fm.u.mail.user))
			fatalx("mfa_session_proceed: MAIL: user truncation");
		if (strlcpy(fm.u.mail.domain, ms->data.evp.sender.domain,
			sizeof(fm.u.mail.domain)) >= sizeof(fm.u.mail.domain))
			fatalx("mfa_session_proceed: MAIL: domain truncation");
		break;

	case HOOK_RCPT:
		if (strlcpy(fm.u.mail.user, ms->data.evp.rcpt.user,
			sizeof(fm.u.mail.user)) >= sizeof(fm.u.mail.user))
			fatalx("mfa_session_proceed: RCPT: user truncation");
		if (strlcpy(fm.u.mail.domain, ms->data.evp.rcpt.domain,
			sizeof(fm.u.mail.domain)) >= sizeof(fm.u.mail.domain))
			fatalx("mfa_session_proceed: RCPT: domain truncation");
		break;

	case HOOK_HEADERLINE:
		if (strlcpy(fm.u.headerline.line, ms->data.buffer,
			sizeof(fm.u.headerline.line))
		    >= sizeof(fm.u.headerline.line))
			fatalx("mfa_session_proceed: HEADER: line truncation");
		break;

	case HOOK_DATALINE:
		if (strlcpy(fm.u.dataline.line, ms->data.buffer,
			sizeof(fm.u.dataline.line))
		    >= sizeof(fm.u.dataline.line))
			fatalx("mfa_session_proceed: DATA: line truncation");
		break;

	case HOOK_QUIT:
	case HOOK_CLOSE:
	case HOOK_RSET:
	case HOOK_DATA:
	case HOOK_EOH:
		break;

	default:
		fatalx("mfa_session_proceed: no such state");
	}

	imsg_compose(filter->process->ibuf, ms->hook, 0, 0, -1, &fm, sizeof(fm));
	imsgproc_set_read_write(filter->process);
}

static void
mfa_session_pickup(struct mfa_session *ms)
{
	if ((ms->fhook = SIMPLEQ_NEXT((struct fhook *)ms->fhook, entry)) == NULL)
		mfa_session_done(ms);
	else
		mfa_session_proceed(ms);
}

static void
mfa_session_done(struct mfa_session *ms)
{
	enum imsg_type		imsg_type;
	struct mfa_resp_msg	resp;

	switch (ms->hook) {
	case HOOK_CONNECT:
		imsg_type = IMSG_MFA_CONNECT;
		break;
	case HOOK_HELO:
		imsg_type = IMSG_MFA_HELO;
		break;
	case HOOK_MAIL:
		imsg_type = IMSG_MFA_MAIL;
		resp.u.mailaddr = ms->data.evp.sender;
		break;
	case HOOK_RCPT:
		if (ms->status == FILTER_OK) {
			imsg_compose_event(env->sc_ievs[PROC_LKA],
			    IMSG_LKA_EXPAND_RCPT, 0, 0, -1,
			    &ms->data.evp, sizeof(ms->data.evp));
                        mfa_session_destroy(ms);
                        return;
		}
		resp.u.mailaddr = ms->data.evp.rcpt;
		imsg_type = IMSG_MFA_RCPT;
		break;
	case HOOK_DATA:
		imsg_type = IMSG_MFA_DATA;
		break;
	case HOOK_HEADERLINE:
		if (ms->status == FILTER_OK) {
			(void)strlcpy(resp.u.buffer,
			    ms->fm.u.headerline.line,
			    sizeof(resp.u.buffer));
		}
		imsg_type = IMSG_MFA_HEADERLINE;
		break;
	case HOOK_DATALINE:
		if (ms->status == FILTER_OK) {
			(void)strlcpy(resp.u.buffer,
			    ms->fm.u.dataline.line,
			    sizeof(resp.u.buffer));
		}
		imsg_type = IMSG_MFA_DATALINE;
		break;
	case HOOK_QUIT:
		imsg_type = IMSG_MFA_QUIT;
		break;
	case HOOK_CLOSE:
		mfa_session_destroy(ms);
		return;
	case HOOK_RSET:
		imsg_type = IMSG_MFA_RSET;
		break;
	case HOOK_EOH:
		imsg_type = IMSG_MFA_EOH;
		break;
	default:
		fatalx("mda_session_done: unsupported state");
	}

	resp.reqid = ms->id;
	switch (ms->status) {
	case FILTER_OK:
		resp.status = MFA_OK;
		break;
	case FILTER_TEMPFAIL:
		resp.status = MFA_TEMPFAIL;
		resp.code = 421;
		break;
	default:
		resp.status = MFA_PERMFAIL;
		resp.code = 530;
		break;
	}

	if (ms->code)
		resp.code = ms->code;

	if (ms->status != FILTER_OK)
		memcpy(resp.u.buffer, ms->errorline, sizeof resp.u.buffer);

	imsg_compose_event(env->sc_ievs[PROC_SMTP], imsg_type, 0, 0,
	    -1, &resp, sizeof(resp));
	mfa_session_destroy(ms);
}

static void
mfa_session_fail(struct mfa_session *ms, enum filter_status status, uint32_t code, char *errorline)
{
	ms->status = status;
	if (code)
		ms->code = code;
	strlcpy(ms->errorline, errorline, sizeof ms->errorline);
	mfa_session_done(ms);
}

static void
mfa_session_destroy(struct mfa_session *ms)
{
	tree_xpop(&sessions, ms->id);
	free(ms);
}

void
mfa_session_imsg_handler(struct imsg *imsg, void *arg)
{
	struct mfa_session	*ms;
	struct filter_msg	*fm;

	if (imsg->hdr.type == HOOK_REGISTER) {
		mfa_session_filter_register(*(uint32_t *)imsg->data, arg);
		return;
	}

	fm = imsg->data;
	ms = tree_xget(&sessions, fm->id);

	if (fm->status != FILTER_OK) {
		mfa_session_fail(ms, fm->status, fm->code, fm->errorline);
		return;
	}

	/* XXX - needs to be completed */

	mfa_session_pickup(ms);
}
