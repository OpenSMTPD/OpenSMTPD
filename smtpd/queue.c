/*	$OpenBSD: queue.c,v 1.141 2012/11/12 14:58:53 eric Exp $	*/

/*
 * Copyright (c) 2008 Gilles Chehade <gilles@poolp.org>
 * Copyright (c) 2008 Pierre-Yves Ritschard <pyr@openbsd.org>
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
#include <sys/stat.h>

#include <err.h>
#include <event.h>
#include <imsg.h>
#include <inttypes.h>
#include <libgen.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "smtpd.h"
#include "log.h"

static void queue_imsg(struct mproc *, struct imsg *);
static void queue_timeout(int, short, void *);
static void queue_bounce(struct envelope *, struct delivery_bounce *);
static void queue_shutdown(void);
static void queue_sig_handler(int, short, void *);

static struct tree	files;

static void
queue_imsg(struct mproc *p, struct imsg *imsg)
{
	struct delivery_bounce	 bounce;
	struct bounce_req_msg	*req_bounce;
	struct queue_req_msg	*req;
	struct queue_data_msg	*data;
	struct queue_resp_msg	 resp;
	struct envelope		*e, evp;
	struct evpstate		*state;
	static uint64_t		 batch_id;
	int			 fd, ret;
	uint64_t		 id;
	uint32_t		 msgid;
	FILE			*ofile;
	size_t			 n;

	if (p->proc == PROC_SMTP) {

		switch (imsg->hdr.type) {
		case IMSG_QUEUE_CREATE_MESSAGE:
			req = imsg->data;
			ret = queue_message_create(&msgid);
			resp.reqid = req->reqid;
			resp.success = (ret == 0) ? 0 : 1;
			resp.evpid = (ret == 0) ? 0 : msgid_to_evpid(msgid);
			m_compose(p, IMSG_QUEUE_CREATE_MESSAGE, 0, 0, -1,
			    &resp, sizeof resp);
			return;

		case IMSG_QUEUE_REMOVE_MESSAGE:
			req = imsg->data;
			msgid = evpid_to_msgid(req->evpid);
			if ((ofile = tree_pop(&files, msgid)))
				fclose(ofile);
			queue_message_delete(msgid);
			m_compose(p_scheduler, IMSG_QUEUE_REMOVE_MESSAGE,
			    0, 0, -1, &msgid, sizeof msgid);
			return;

		case IMSG_QUEUE_COMMIT_MESSAGE:
			req = imsg->data;
			msgid = evpid_to_msgid(req->evpid);
			ret = 1;
			if ((ofile = tree_xpop(&files, msgid)) == NULL)
				ret = 0; /* fwrite failed */
			else
				ret = safe_fclose(ofile);
			if (ret)
				ret = queue_message_commit(msgid);
			resp.reqid = req->reqid;
			resp.success = (ret == 0) ? 0 : 1;
			resp.evpid = msgid_to_evpid(msgid);
			m_compose(p, IMSG_QUEUE_COMMIT_MESSAGE, 0, 0, -1,
			    &resp, sizeof resp);
			if (resp.success)
				m_compose(p_scheduler,
				    IMSG_QUEUE_COMMIT_MESSAGE, 0, 0, -1,
				    &msgid, sizeof msgid);
			return;

		case IMSG_QUEUE_MESSAGE_FILE:
			req = imsg->data;
			msgid = evpid_to_msgid(req->evpid);
			fd = queue_message_fd_rw(msgid);
			if (fd != -1) {
				ofile = fdopen(fd, "w");
				if (ofile == NULL) {
					close(fd);
					fd = -1;
				}
				else
					tree_xset(&files, msgid, ofile);
			}
			resp.reqid = req->reqid;
			resp.success = (fd == -1) ? 0 : 1;
			resp.evpid = req->evpid;
			m_compose(p, IMSG_QUEUE_MESSAGE_FILE, 0, 0, -1,
			    &resp, sizeof resp);
			return;

		case IMSG_QUEUE_DATA:
			data = imsg->data;
			ofile = tree_xget(&files, data->msgid);
			if (ofile == NULL)
				return;

			/* XXX plug compression/crypto */

			n = fwrite(data->data, 1, data->len, ofile);
			if (n != data->len) {
				log_warn("warn: failed to write message data");
				fclose(ofile);
				tree_xset(&files, data->msgid, NULL);
				/* XXX report to SMTP */
			}
			return;

		case IMSG_SMTP_ENQUEUE_FD:
			id = *(uint64_t*)(imsg->data);
			bounce_run(id, imsg->fd);
			return;
		}
	}

	if (p->proc == PROC_LKA) {
		switch (imsg->hdr.type) {
		case IMSG_QUEUE_SUBMIT_ENVELOPE:
			e = imsg->data;
			ret = queue_envelope_create(e);
			resp.reqid = e->session_id;
			resp.success = (ret == 0) ? 0 : 1;
			resp.evpid = (ret == 0) ? 0 : e->id;
			m_compose(p_smtp, IMSG_QUEUE_SUBMIT_ENVELOPE, 0, 0, -1,
			    &resp, sizeof resp);
			if (resp.success)
				m_compose(p_scheduler,
				    IMSG_QUEUE_SUBMIT_ENVELOPE, 0, 0, -1, e,
				    sizeof *e);
			return;

		case IMSG_QUEUE_COMMIT_ENVELOPES:
			e = imsg->data;
			resp.reqid = e->session_id;
			resp.success = 1;
			resp.evpid = 0;
			m_compose(p_smtp, IMSG_QUEUE_COMMIT_ENVELOPES, 0, 0, -1,
			    &resp, sizeof resp);
			return;
		}
	}

	if (p->proc == PROC_SCHEDULER) {
		switch (imsg->hdr.type) {
		case IMSG_QUEUE_REMOVE:
			id = *(uint64_t*)(imsg->data);
			if (queue_envelope_load(id, &evp) == 0)
				errx(1, "cannot load evp:%016" PRIx64, id);
			log_envelope(&evp, NULL, "Remove",
			    "Removed by administrator");
			queue_envelope_delete(&evp);
			return;

		case IMSG_QUEUE_EXPIRE:
			id = *(uint64_t*)(imsg->data);
			if (queue_envelope_load(id, &evp) == 0)
				errx(1, "cannot load evp:%016" PRIx64, id);
			envelope_set_errormsg(&evp, "Envelope expired");
			bounce.type = B_ERROR;
			bounce.delay = 0;
			bounce.expire = 0;
			queue_bounce(&evp, &bounce);
			log_envelope(&evp, NULL, "Expire", evp.errorline);
			queue_envelope_delete(&evp);
			return;

		case IMSG_QUEUE_BOUNCE:
			req_bounce = imsg->data;
			id = req_bounce->evpid;
			if (queue_envelope_load(id, &evp) == 0)
				errx(1, "cannot load evp:%016" PRIx64, id);
			queue_bounce(&evp, &req_bounce->bounce);
			evp.lastbounce = req_bounce->timestamp;
			queue_envelope_update(&evp);
			return;

		case IMSG_MDA_DELIVER:
			id = *(uint64_t*)(imsg->data);
			if (queue_envelope_load(id, &evp) == 0)
				errx(1, "cannot load evp:%016" PRIx64, id);
			evp.lasttry = time(NULL);
			m_compose(p_mda, IMSG_MDA_DELIVER, 0, 0, -1,
			    &evp, sizeof evp);
			return;

		case IMSG_BOUNCE_INJECT:
			id = *(uint64_t*)(imsg->data);
			bounce_add(id);
			return;

		case IMSG_MTA_BATCH:
			batch_id = generate_uid();
			m_compose(p_mta, IMSG_MTA_BATCH, 0, 0, -1,
			    &batch_id, sizeof batch_id);
			return;

		case IMSG_MTA_BATCH_ADD:
			id = *(uint64_t*)(imsg->data);
			if (queue_envelope_load(id, &evp) == 0)
				errx(1, "cannot load evp:%016" PRIx64, id);
			evp.lasttry = time(NULL);
			evp.batch_id = batch_id;
			m_compose(p_mta, IMSG_MTA_BATCH_ADD, 0, 0, -1,
			    &evp, sizeof evp);
			return;

		case IMSG_MTA_BATCH_END:
			m_compose(p_mta, IMSG_MTA_BATCH_END, 0, 0, -1,
			    &batch_id, sizeof batch_id);
			return;

		case IMSG_CTL_LIST_ENVELOPES:
			if (imsg->hdr.len == sizeof imsg->hdr) {
				m_forward(p_control, imsg);
				return;
			}
			state = imsg->data;
			if (queue_envelope_load(state->evpid, &evp) == 0)
				return; /* Envelope is gone, drop it */
			/*
			 * XXX consistency: The envelope might already be on
			 * its way back to the scheduler.  We need to detect
			 * this properly and report that state.
			 */
			evp.flags |= state->flags;
			/* In the past if running or runnable */
			evp.nexttry = state->time;
			if (state->flags == EF_INFLIGHT) {
				/*
				 * Not exactly correct but pretty close: The
				 * value is not recorded on the envelope unless
				 * a tempfail occurs.
				 */
				evp.lasttry = state->time;
			}
			m_compose(p_control, IMSG_CTL_LIST_ENVELOPES,
			    imsg->hdr.peerid, 0, -1, &evp, sizeof evp);
			return;
		}
	}

	if (p->proc == PROC_MTA || p->proc == PROC_MDA) {
		switch (imsg->hdr.type) {
		case IMSG_QUEUE_MESSAGE_FD:
			fd = queue_message_fd_r(imsg->hdr.peerid);
			m_compose(p,  IMSG_QUEUE_MESSAGE_FD, 0, 0, fd,
			    imsg->data, imsg->hdr.len - sizeof imsg->hdr);
			return;

		case IMSG_DELIVERY_OK:
			e = imsg->data;
			queue_envelope_delete(e);
			m_compose(p_scheduler, IMSG_DELIVERY_OK, 0, 0, -1,
			    &e->id, sizeof e->id);
			return;

		case IMSG_DELIVERY_TEMPFAIL:
			e = imsg->data;
			e->retry++;
			queue_envelope_update(e);
			m_compose(p_scheduler, IMSG_DELIVERY_TEMPFAIL, 0, 0, -1,
			    e, sizeof *e);
			return;

		case IMSG_DELIVERY_PERMFAIL:
			e = imsg->data;
			bounce.type = B_ERROR;
			bounce.delay = 0;
			bounce.expire = 0;
			queue_bounce(&evp, &bounce);
			queue_envelope_delete(e);
			m_compose(p_scheduler, IMSG_DELIVERY_PERMFAIL, 0, 0, -1,
			&e->id, sizeof e->id);
			return;

		case IMSG_DELIVERY_LOOP:
			e = imsg->data;
			bounce.type = B_ERROR;
			bounce.delay = 0;
			bounce.expire = 0;
			queue_bounce(&evp, &bounce);
			queue_envelope_delete(e);
			m_compose(p_scheduler, IMSG_DELIVERY_LOOP, 0, 0, -1,
			    &e->id, sizeof e->id);
			return;
		}
	}

	if (p->proc == PROC_CONTROL) {
		switch (imsg->hdr.type) {
		case IMSG_CTL_PAUSE_MDA:
		case IMSG_CTL_PAUSE_MTA:
		case IMSG_CTL_RESUME_MDA:
		case IMSG_CTL_RESUME_MTA:
		case IMSG_QUEUE_REMOVE:
			m_forward(p_scheduler, imsg);
			return;
		}
	}

	if (p->proc == PROC_PARENT) {
		switch (imsg->hdr.type) {
		case IMSG_CTL_VERBOSE:
			log_verbose(*(int *)imsg->data);
			m_forward(p_scheduler, imsg);
			return;
		}
	}

	errx(1, "queue_imsg: unexpected %s imsg", imsg_to_str(imsg->hdr.type));
}

static void
queue_bounce(struct envelope *e, struct delivery_bounce *d)
{
	struct envelope	b;
	uint32_t	msgid;

	b = *e;
	b.type = D_BOUNCE;
	b.agent.bounce = *d;
	b.retry = 0;
	b.lasttry = 0;
	b.creation = time(NULL);
	b.expire = 3600 * 24 * 7;

	if (e->type == D_BOUNCE) {
		log_warnx("warn: queue: double bounce!");
	} else if (e->sender.user[0] == '\0') {
		log_warnx("warn: queue: no return path!");
	} else if (!queue_envelope_create(&b)) {
		log_warnx("warn: queue: cannot bounce!");
	} else {
		log_debug("debug: queue: bouncing evp:%016" PRIx64
		    " as evp:%016" PRIx64, e->id, b.id);
		m_compose(p_scheduler, IMSG_QUEUE_SUBMIT_ENVELOPE, 0, 0, -1,
		    &b, sizeof b);
		msgid = evpid_to_msgid(b.id);
		m_compose(p_scheduler, IMSG_QUEUE_COMMIT_MESSAGE, 0, 0, -1,
		    &msgid, sizeof msgid);
		stat_increment("queue.bounce", 1);
	}
}

static void
queue_sig_handler(int sig, short event, void *p)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		queue_shutdown();
		break;
	default:
		fatalx("queue_sig_handler: unexpected signal");
	}
}

static void
queue_shutdown(void)
{
	log_info("info: queue handler exiting");
	_exit(0);
}

pid_t
queue(void)
{
	pid_t		 pid;
	struct passwd	*pw;
	struct timeval	 tv;
	struct event	 ev_qload;
	struct event	 ev_sigint;
	struct event	 ev_sigterm;

	switch (pid = fork()) {
	case -1:
		fatal("queue: cannot fork");
	case 0:
		env->sc_pid = getpid();
		break;
	default:
		return (pid);
	}

	purge_config(PURGE_EVERYTHING);
	if (env->sc_pwqueue) {
		free(env->sc_pw);
		env->sc_pw = env->sc_pwqueue;
	}

	pw = env->sc_pw;
	if (chroot(PATH_SPOOL) == -1)
		fatal("queue: chroot");
	if (chdir("/") == -1)
		fatal("queue: chdir(\"/\")");

	smtpd_process = PROC_QUEUE;
	setproctitle("%s", env->sc_title[smtpd_process]);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("queue: cannot drop privileges");

	imsg_callback = queue_imsg;
	event_init();

	signal_set(&ev_sigint, SIGINT, queue_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, queue_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	fdlimit(1.0);

	config_peer(PROC_PARENT);
	config_peer(PROC_CONTROL);
	config_peer(PROC_SMTP);
	config_peer(PROC_MDA);
	config_peer(PROC_MTA);
	config_peer(PROC_LKA);
	config_peer(PROC_SCHEDULER);
	config_done();

	/* setup queue loading task */
	evtimer_set(&ev_qload, queue_timeout, &ev_qload);
	tv.tv_sec = 0;
	tv.tv_usec = 10;
	evtimer_add(&ev_qload, &tv);

	if (event_dispatch() <  0)
		fatal("event_dispatch");
	queue_shutdown();

	return (0);
}

static void
queue_timeout(int fd, short event, void *p)
{
	static uint32_t	 msgid = 0;
	struct envelope	 evp;
	struct event	*ev = p;
	struct timeval	 tv;
	int		 r;

	r = queue_envelope_walk(&evp);
	if (r == -1) {
		if (msgid)
			m_compose(p_scheduler, IMSG_QUEUE_COMMIT_MESSAGE,
			    0, 0, -1, &msgid, sizeof msgid);
		log_debug("debug: queue: done loading queue into scheduler");
		return;
	}

	if (r) {
		if (msgid && evpid_to_msgid(evp.id) != msgid)
			m_compose(p_scheduler, IMSG_QUEUE_COMMIT_MESSAGE,
			    0, 0, -1, &msgid, sizeof msgid);
		msgid = evpid_to_msgid(evp.id);
		m_compose(p_scheduler, IMSG_QUEUE_SUBMIT_ENVELOPE, 0, 0, -1,
		    &evp, sizeof evp);
	}

	tv.tv_sec = 0;
	tv.tv_usec = 10;
	evtimer_add(ev, &tv);
}
