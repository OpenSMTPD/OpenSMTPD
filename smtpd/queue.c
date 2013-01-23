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

static void
queue_imsg(struct mproc *p, struct imsg *imsg)
{
	struct delivery_bounce	 bounce;
	struct bounce_req_msg	*req_bounce;
	struct envelope		 evp;
	static uint64_t		 batch_id;
	struct msg		 m;
	uint64_t		 reqid, evpid;
	uint32_t		 msgid;
	time_t			 nexttry;
	int			 fd, ret, v, flags;

	if (p->proc == PROC_SMTP) {

		switch (imsg->hdr.type) {
		case IMSG_QUEUE_CREATE_MESSAGE:
			m_msg(&m, imsg);
			m_get_id(&m, &reqid);
			m_end(&m);

			ret = queue_message_create(&msgid);

			m_create(p, IMSG_QUEUE_CREATE_MESSAGE, 0, 0, -1, 24);
			m_add_id(p, reqid);
			if (ret == 0)
				m_add_int(p, 0);
			else {
				m_add_int(p, 1);
				m_add_msgid(p, msgid);
			}
			m_close(p);
			return;

		case IMSG_QUEUE_REMOVE_MESSAGE:
			m_msg(&m, imsg);
			m_get_msgid(&m, &msgid);
			m_end(&m);

			queue_message_delete(msgid);

			m_create(p_scheduler, IMSG_QUEUE_REMOVE_MESSAGE,
			    0, 0, -1, 5);
			m_add_msgid(p_scheduler, msgid);
			m_close(p_scheduler);
			return;

		case IMSG_QUEUE_COMMIT_MESSAGE:
			m_msg(&m, imsg);
			m_get_id(&m, &reqid);
			m_get_msgid(&m, &msgid);
			m_end(&m);

			ret = queue_message_commit(msgid);

			m_create(p,  IMSG_QUEUE_COMMIT_MESSAGE, 0, 0, -1, 16);
			m_add_id(p, reqid);
			m_add_int(p, (ret == 0) ? 0 : 1);
			m_close(p);

			if (ret) {
				m_create(p_scheduler, IMSG_QUEUE_COMMIT_MESSAGE,
				    0, 0, -1, 5);
				m_add_msgid(p_scheduler, msgid);
				m_close(p_scheduler);
			}
			return;

		case IMSG_QUEUE_MESSAGE_FILE:
			m_msg(&m, imsg);
			m_get_id(&m, &reqid);
			m_get_msgid(&m, &msgid);
			m_end(&m);

			fd = queue_message_fd_rw(msgid);

			m_create(p, IMSG_QUEUE_MESSAGE_FILE, 0, 0, fd, 16);
			m_add_id(p, reqid);
			m_add_int(p, (fd == -1) ? 0 : 1);
			m_close(p);
			return;

		case IMSG_SMTP_ENQUEUE_FD:
			bounce_fd(imsg->fd);
			return;
		}
	}

	if (p->proc == PROC_LKA) {
		switch (imsg->hdr.type) {
		case IMSG_QUEUE_SUBMIT_ENVELOPE:
			m_msg(&m, imsg);
			m_get_id(&m, &reqid);
			m_get_envelope(&m, &evp);
			m_end(&m);
		    
			if (evp.id == 0)
				log_warn("warn: imsg_queue_submit_envelope: evpid=0");
			if (evpid_to_msgid(evp.id) == 0)
				log_warn("warn: imsg_queue_submit_envelope: msgid=0, "
				    "evpid=%016"PRIx64, evp.id);
			ret = queue_envelope_create(&evp);
			m_create(p_smtp, IMSG_QUEUE_SUBMIT_ENVELOPE, 0, 0, -1,
			    24);
			m_add_id(p_smtp, reqid);
			if (ret == 0)
				m_add_int(p_smtp, 0);
			else {
				m_add_int(p_smtp, 1);
				m_add_evpid(p_smtp, evp.id);
			}
			m_close(p_smtp);
			if (ret) {
				m_create(p_scheduler,
				    IMSG_QUEUE_SUBMIT_ENVELOPE, 0, 0, -1,
				    MSZ_EVP);
				m_add_envelope(p_scheduler, &evp);
				m_close(p_scheduler);

			}
			return;

		case IMSG_QUEUE_COMMIT_ENVELOPES:
			m_msg(&m, imsg);
			m_get_id(&m, &reqid);
			m_end(&m);
			m_create(p_smtp, IMSG_QUEUE_COMMIT_ENVELOPES, 0, 0, -1,
			    16);
			m_add_id(p_smtp, reqid);
			m_add_int(p_smtp, 1);
			m_close(p_smtp);
			return;
		}
	}

	if (p->proc == PROC_SCHEDULER) {
		switch (imsg->hdr.type) {
		case IMSG_QUEUE_REMOVE:
			m_msg(&m, imsg);
			m_get_evpid(&m, &evpid);
			m_end(&m);
			if (queue_envelope_load(evpid, &evp) == 0)
				errx(1, "cannot load evp:%016" PRIx64, evpid);
			log_envelope(&evp, NULL, "Remove",
			    "Removed by administrator");
			queue_envelope_delete(evpid);
			return;

		case IMSG_QUEUE_EXPIRE:
			m_msg(&m, imsg);
			m_get_evpid(&m, &evpid);
			m_end(&m);
			if (queue_envelope_load(evpid, &evp) == 0)
				errx(1, "cannot load evp:%016" PRIx64, evpid);
			envelope_set_errormsg(&evp, "Envelope expired");
			bounce.type = B_ERROR;
			bounce.delay = 0;
			bounce.expire = 0;
			queue_bounce(&evp, &bounce);
			log_envelope(&evp, NULL, "Expire", evp.errorline);
			queue_envelope_delete(evpid);
			return;

		case IMSG_QUEUE_BOUNCE:
			req_bounce = imsg->data;
			evpid = req_bounce->evpid;
			if (queue_envelope_load(evpid, &evp) == 0)
				errx(1, "cannot load evp:%016" PRIx64, evpid);
			queue_bounce(&evp, &req_bounce->bounce);
			evp.lastbounce = req_bounce->timestamp;
			queue_envelope_update(&evp);
			return;

		case IMSG_MDA_DELIVER:
			m_msg(&m, imsg);
			m_get_evpid(&m, &evpid);
			m_end(&m);
			if (queue_envelope_load(evpid, &evp) == 0)
				errx(1, "cannot load evp:%016" PRIx64, evpid);
			evp.lasttry = time(NULL);
			m_create(p_mda, IMSG_MDA_DELIVER, 0, 0, -1, MSZ_EVP);
			m_add_envelope(p_mda, &evp);
			m_close(p_mda);
			return;

		case IMSG_BOUNCE_INJECT:
			m_msg(&m, imsg);
			m_get_evpid(&m, &evpid);
			m_end(&m);
			bounce_add(evpid);
			return;

		case IMSG_MTA_BATCH:
			batch_id = generate_uid();
			m_create(p_mta, IMSG_MTA_BATCH, 0, 0, -1, 9);
			m_add_id(p_mta, batch_id);
			m_close(p_mta);
			return;

		case IMSG_MTA_BATCH_ADD:
			m_msg(&m, imsg);
			m_get_evpid(&m, &evpid);
			m_end(&m);
			if (queue_envelope_load(evpid, &evp) == 0)
				errx(1, "cannot load evp:%016" PRIx64, evpid);
			evp.lasttry = time(NULL);
			m_create(p_mta, IMSG_MTA_BATCH_ADD, 0, 0, -1, MSZ_EVP);
			m_add_id(p_mta, batch_id);
			m_add_envelope(p_mta, &evp);
			m_close(p_mta);
			return;

		case IMSG_MTA_BATCH_END:
			m_create(p_mta, IMSG_MTA_BATCH_END, 0, 0, -1, 9);
			m_add_id(p_mta, batch_id);
			m_close(p_mta);
			return;

		case IMSG_CTL_LIST_ENVELOPES:
			if (imsg->hdr.len == sizeof imsg->hdr) {
				m_forward(p_control, imsg);
				return;
			}

			m_msg(&m, imsg);
			m_get_evpid(&m, &evpid);
			m_get_int(&m, &flags);
			m_get_time(&m, &nexttry);
			m_end(&m);

			if (queue_envelope_load(evpid, &evp) == 0)
				return; /* Envelope is gone, drop it */

			/*
			 * XXX consistency: The envelope might already be on
			 * its way back to the scheduler.  We need to detect
			 * this properly and report that state.
			 */
			evp.flags |= flags;
			/* In the past if running or runnable */
			evp.nexttry = nexttry;
			if (flags == EF_INFLIGHT) {
				/*
				 * Not exactly correct but pretty close: The
				 * value is not recorded on the envelope unless
				 * a tempfail occurs.
				 */
				evp.lasttry = nexttry;
			}
			m_compose(p_control, IMSG_CTL_LIST_ENVELOPES,
			    imsg->hdr.peerid, 0, -1, &evp, sizeof evp);
			return;
		}
	}

	if (p->proc == PROC_MTA || p->proc == PROC_MDA) {
		switch (imsg->hdr.type) {
		case IMSG_QUEUE_MESSAGE_FD:
			m_msg(&m, imsg);
			m_get_id(&m, &reqid);
			m_get_msgid(&m, &msgid);
			m_end(&m);
			fd = queue_message_fd_r(msgid);
			m_create(p, IMSG_QUEUE_MESSAGE_FD, 0, 0, fd, 25);
			m_add_id(p, reqid);
			m_close(p);
			return;

		case IMSG_DELIVERY_OK:
			m_msg(&m, imsg);
			m_get_envelope(&m, &evp);
			m_end(&m);
			queue_envelope_delete(evp.id);
			m_create(p_scheduler, IMSG_DELIVERY_OK, 0, 0, -1, 9);
			m_add_evpid(p_scheduler, evp.id);
			m_close(p_scheduler);
			return;

		case IMSG_DELIVERY_TEMPFAIL:
			m_msg(&m, imsg);
			m_get_envelope(&m, &evp);
			m_end(&m);
			evp.retry++;
			queue_envelope_update(&evp);
			m_create(p_scheduler, IMSG_DELIVERY_TEMPFAIL, 0, 0, -1,
			    MSZ_EVP);
			m_add_envelope(p_scheduler, &evp);
			m_close(p_scheduler);
			return;

		case IMSG_DELIVERY_PERMFAIL:
			m_msg(&m, imsg);
			m_get_envelope(&m, &evp);
			m_end(&m);
			bounce.type = B_ERROR;
			bounce.delay = 0;
			bounce.expire = 0;
			queue_bounce(&evp, &bounce);
			queue_envelope_delete(evp.id);
			m_create(p_scheduler, IMSG_DELIVERY_PERMFAIL, 0, 0, -1,
			    9);
			m_add_evpid(p_scheduler, evp.id);
			m_close(p_scheduler);
			return;

		case IMSG_DELIVERY_LOOP:
			m_msg(&m, imsg);
			m_get_envelope(&m, &evp);
			m_end(&m);
			bounce.type = B_ERROR;
			bounce.delay = 0;
			bounce.expire = 0;
			queue_bounce(&evp, &bounce);
			queue_envelope_delete(evp.id);
			m_create(p_scheduler, IMSG_DELIVERY_LOOP, 0, 0, -1, 9);
			m_add_evpid(p_scheduler, evp.id);
			m_close(p_scheduler);
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
			m_msg(&m, imsg);
			m_get_int(&m, &v);
			m_end(&m);
			log_verbose(v);
			m_forward(p_scheduler, imsg);
			return;

		case IMSG_CTL_PROFILE:
			m_msg(&m, imsg);
			m_get_int(&m, &v);
			m_end(&m);
			profiling = v;
			return;
		}
	}

	errx(1, "queue_imsg: unexpected %s imsg", imsg_to_str(imsg->hdr.type));
}

static void
queue_bounce(struct envelope *e, struct delivery_bounce *d)
{
	struct envelope	b;

	b = *e;
	b.type = D_BOUNCE;
	b.agent.bounce = *d;
	b.retry = 0;
	b.lasttry = 0;
	b.creation = time(NULL);
	b.expire = 3600 * 24 * 7;

	if (b.id == 0)
		log_warn("warn: queue_bounce: evpid=0");
	if (evpid_to_msgid(b.id) == 0)
		log_warn("warn: queue_bounce: msgid=0, evpid=%016"PRIx64,
			b.id);
	if (e->type == D_BOUNCE) {
		log_warnx("warn: queue: double bounce!");
	} else if (e->sender.user[0] == '\0') {
		log_warnx("warn: queue: no return path!");
	} else if (!queue_envelope_create(&b)) {
		log_warnx("warn: queue: cannot bounce!");
	} else {
		log_debug("debug: queue: bouncing evp:%016" PRIx64
		    " as evp:%016" PRIx64, e->id, b.id);

		m_create(p_scheduler, IMSG_QUEUE_SUBMIT_ENVELOPE, 0, 0, -1,
		    MSZ_EVP);
		m_add_envelope(p_scheduler, &b);
		m_close(p_scheduler);

		m_create(p_scheduler, IMSG_QUEUE_COMMIT_MESSAGE, 0, 0, -1, 5);
		m_add_msgid(p_scheduler, evpid_to_msgid(b.id));
		m_close(p_scheduler);

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

	config_process(PROC_QUEUE);

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
		if (msgid) {
			m_create(p_scheduler, IMSG_QUEUE_COMMIT_MESSAGE,
			    0, 0, -1, 5);
			m_add_msgid(p_scheduler, msgid);
			m_close(p_scheduler);
		}
		log_debug("debug: queue: done loading queue into scheduler");
		return;
	}

	if (r) {
		if (msgid && evpid_to_msgid(evp.id) != msgid) {
			m_create(p_scheduler, IMSG_QUEUE_COMMIT_MESSAGE,
			    0, 0, -1, 5);
			m_add_msgid(p_scheduler, msgid);
			m_close(p_scheduler);
		}
		msgid = evpid_to_msgid(evp.id);
		m_create(p_scheduler, IMSG_QUEUE_SUBMIT_ENVELOPE, 0, 0, -1,
		    MSZ_EVP);
		m_add_envelope(p_scheduler, &evp);
		m_close(p_scheduler);
	}

	tv.tv_sec = 0;
	tv.tv_usec = 10;
	evtimer_add(ev, &tv);
}
