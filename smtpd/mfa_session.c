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
static void mfa_session_fail(struct mfa_session *, uint32_t, char *);

static void mfa_session_filter_register(uint32_t, struct filter *);
void mfa_session_imsg_handler(struct imsg *, void *);

struct fhook {
	SIMPLEQ_ENTRY(fhook)	entry;
	struct filter	       *filter;
};

/* XXX - needs to be update to match the number of filter_type in smtpd-api.h */
SIMPLEQ_HEAD(flist, fhook)	filter_hooks[9];

void
mfa_session_filters_init(void)
{
	struct filter  *filter;
	void	       *iter;
	size_t		i;

	for (i = 0; i < nitems(filter_hooks); ++i)
		SIMPLEQ_INIT(&filter_hooks[i]);

	iter = NULL;
	while (dict_iter(&env->sc_filters, &iter, NULL, (void **)&filter)) {
		filter->process = imsgproc_fork(filter->path, filter->name,
		    mfa_session_imsg_handler, filter);
		if (filter->process == NULL)
			fatalx("could not start filter");
		imsgproc_set_read(filter->process);
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
}

void
mfa_session(struct submit_status *ss, enum filter_type hook)
{
	struct mfa_session     *ms;
	uint32_t	       	i;

	ms = xcalloc(1, sizeof(*ms), "mfa_session");
	ms->id    = ss->id;
	ms->ss    = *ss;
	ms->hook  = hook;
 	ms->ss.code = 250;
	tree_xset(&env->mfa_sessions, ms->id, ms);

	/* no filter handling this hook */
	if (!(hook & env->filtermask)) {
		mfa_session_done(ms);
		return;
	}

	if ((i = ffs(ms->hook)) == 0)
		fatalx("something strange happened");
	ms->fhook = SIMPLEQ_FIRST(&filter_hooks[i - 1]);
	mfa_session_proceed(ms);
}

static void
mfa_session_proceed(struct mfa_session *ms)
{
	struct filter_msg	fm;
	struct filter	       *filter = ((struct fhook *)ms->fhook)->filter;

	bzero(&fm, sizeof fm);
	fm.id = ms->id;
	fm.version = FILTER_API_VERSION;

	switch (ms->hook) {
	case FILTER_CONNECT:
		if (strlcpy(fm.u.connect.hostname, ms->ss.envelope.hostname,
			sizeof(fm.u.connect.hostname))
		    >= sizeof(fm.u.connect.hostname))
			fatalx("mfa_session_proceed: CONNECT: truncation");
		fm.u.connect.hostaddr = ms->ss.envelope.ss;
		break;

	case FILTER_HELO:
	case FILTER_EHLO:
		if (strlcpy(fm.u.helo.helohost, ms->ss.envelope.helo,
			sizeof(fm.u.helo.helohost))
		    >= sizeof(fm.u.helo.helohost))
			fatalx("mfa_session_proceed: HELO: truncation");
		break;

	case FILTER_MAIL:
		if (strlcpy(fm.u.mail.user, ms->ss.u.maddr.user,
			sizeof(fm.u.mail.user)) >= sizeof(fm.u.mail.user))
			fatalx("mfa_session_proceed: MAIL: user truncation");
		if (strlcpy(fm.u.mail.domain, ms->ss.u.maddr.domain,
			sizeof(fm.u.mail.domain)) >= sizeof(fm.u.mail.domain))
			fatalx("mfa_session_proceed: MAIL: domain truncation");
		break;
		
	case FILTER_RCPT:
		if (strlcpy(fm.u.mail.user, ms->ss.u.maddr.user,
			sizeof(fm.u.mail.user)) >= sizeof(fm.u.mail.user))
			fatalx("mfa_session_proceed: RCPT: user truncation");
		if (strlcpy(fm.u.mail.domain, ms->ss.u.maddr.domain,
			sizeof(fm.u.mail.domain)) >= sizeof(fm.u.mail.domain))
			fatalx("mfa_session_proceed: RCPT: domain truncation");
		break;

	case FILTER_DATALINE:
		if (strlcpy(fm.u.dataline.line, ms->ss.u.dataline,
			sizeof(fm.u.dataline.line))
		    >= sizeof(fm.u.dataline.line))
			fatalx("mfa_session_proceed: DATA: line truncation");
		break;

	case FILTER_QUIT:
	case FILTER_CLOSE:
	case FILTER_RSET:
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
	enum imsg_type	imsg_type;

	if (!ms->ss.code)
		ms->ss.code = 250;

	switch (ms->hook) {
	case FILTER_CONNECT:
		imsg_type = IMSG_MFA_CONNECT;
		break;
	case FILTER_HELO:
	case FILTER_EHLO:
		imsg_type = IMSG_MFA_HELO;
		break;
	case FILTER_MAIL:
		if (! ms->ss.code) {
			imsg_compose_event(env->sc_ievs[PROC_LKA],
                            IMSG_LKA_MAIL, 0, 0, -1,
                            &ms->ss, sizeof(ms->ss));
                        mfa_session_destroy(ms);
                        return;
		}
		imsg_type = IMSG_MFA_MAIL;
		break;
	case FILTER_RCPT:
		if (! ms->ss.code) {
			imsg_compose_event(env->sc_ievs[PROC_LKA],
                            IMSG_LKA_RULEMATCH, 0, 0, -1,
                            &ms->ss, sizeof(ms->ss));
                        mfa_session_destroy(ms);
                        return;
		}
		imsg_type = IMSG_MFA_RCPT;
		break;
	case FILTER_DATALINE:
		imsg_type = IMSG_MFA_DATALINE;
		break;
	case FILTER_QUIT:
		imsg_type = IMSG_MFA_QUIT;
		break;
	case FILTER_CLOSE:
		mfa_session_destroy(ms);
		return;
	case FILTER_RSET:
		imsg_type = IMSG_MFA_RSET;
		break;
	default:
		fatalx("mda_session_done: unsupported state");
	}
	imsg_compose_event(env->sc_ievs[PROC_SMTP], imsg_type, 0, 0,
            -1, &ms->ss, sizeof(struct submit_status));
        mfa_session_destroy(ms);
}

static void
mfa_session_fail(struct mfa_session *ms, uint32_t code, char *errorline)
{
	ms->ss.code = code;
	strlcpy(ms->ss.u.errormsg, errorline, sizeof ms->ss.u.errormsg);
	mfa_session_done(ms);
}

static void
mfa_session_destroy(struct mfa_session *ms)
{
	tree_xpop(&env->mfa_sessions, ms->id);
	free(ms);
}

void
mfa_session_imsg_handler(struct imsg *imsg, void *arg)
{
	struct mfa_session	*ms;
	struct filter_msg	*fm;

	if (imsg->hdr.type == FILTER_REGISTER) {
		mfa_session_filter_register(*(uint32_t *)imsg->data, arg);
		return;
	}

	fm = imsg->data;
	switch (imsg->hdr.type) {
	default:
		fm = imsg->data;
		ms = tree_xget(&env->mfa_sessions, fm->id);
		break;
	}

	if (fm->code) {
		mfa_session_fail(ms, fm->code, fm->errorline);
		return;
	}

	ms->ss.code = fm->code;
	strlcpy(ms->ss.u.errormsg, fm->errorline, sizeof ms->ss.u.errormsg);

	mfa_session_pickup(ms);
}
