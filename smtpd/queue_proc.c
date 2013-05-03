/*	$OpenBSD: queue_fsqueue.c,v 1.53 2012/08/30 18:19:50 eric Exp $	*/

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
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

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

static int queue_proc_init(int);
static int queue_proc_message(enum queue_op, uint32_t *);
static int queue_proc_envelope(enum queue_op , uint64_t *, char *, size_t);
static int queue_proc_call(size_t);

struct queue_backend	queue_backend_proc = {
	queue_proc_init,
	queue_proc_message,
	queue_proc_envelope,
};

static int		 running;
static pid_t		 pid;
static struct imsgbuf	 ibuf;
static struct imsg	 imsg;
static size_t		 rlen;
static char		*rdata;

static const char *path = "/usr/libexec/smtpd/backend-queue";

static int
queue_proc_init(int server)
{
	int		sp[2];
	uint32_t	version;

	errno = 0;

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, sp) < 0) {
		log_warn("warn: queue-proc: socketpair");
		return (0);
	}

	if ((pid = fork()) == -1) {
		log_warn("warn: queue-proc: fork");
		goto err;
	}

	if (pid == 0) {
		/* child process */
		dup2(sp[0], STDIN_FILENO);
		if (closefrom(STDERR_FILENO + 1) < 0)
			exit(1);

		execl(path, "queue_ramproc", NULL);
		err(1, "execl");
	}

	/* parent process */
	close(sp[0]);
	imsg_init(&ibuf, sp[1]);
	running = 1;

	version = PROC_QUEUE_API_VERSION;
	imsg_compose(&ibuf, PROC_QUEUE_INIT, 0, 0, -1,
	    &version, sizeof(version));
	return (queue_proc_call(0));

err:
	close(sp[0]);
	close(sp[1]);
	return (0);
}

static int
queue_proc_message(enum queue_op qop, uint32_t *msgid)
{
	int	r, msg;

	if (!running)
		return (qop == QOP_FD_R || qop == QOP_FD_RW) ? -1 : 0;

	switch (qop) {

	case QOP_CREATE:
		log_debug("debug: queue-proc: PROC_QUEUE_MESSAGE_CREATE");
		imsg_compose(&ibuf, PROC_QUEUE_MESSAGE_CREATE, 0, 0, -1,
		    NULL, 0);

		if (!queue_proc_call(-1))
			return (0);
		if (rlen < sizeof(r)) {
			return (0);
		}
		memmove(&r, rdata, sizeof(r));
		rdata += sizeof(r);
		rlen -= sizeof(r);
		if (r != 1) {
			if (rlen)
				log_warnx("warn: queue-proc: bogus data");
			return (r);
		}

		if (rlen < sizeof(*msgid)) {
			return (0);
		}
		memmove(msgid, rdata, sizeof(*msgid));
		rdata += sizeof(*msgid);
		rlen -= sizeof(*msgid);
		if (rlen)
			log_warnx("warn: queue-proc: bogus data");

		return (r);

	case QOP_DELETE:
	case QOP_COMMIT:

		if (qop == QOP_DELETE) {
			log_debug("debug: queue-proc: PROC_QUEUE_MESSAGE_DELETE");
			msg = PROC_QUEUE_MESSAGE_DELETE;
		}
		else {
			log_debug("debug: queue-proc: PROC_QUEUE_MESSAGE_COMMIT");
			msg = PROC_QUEUE_MESSAGE_COMMIT;
		}

		imsg_compose(&ibuf, msg, 0, 0, -1, msgid, sizeof(*msgid));
		if (!queue_proc_call(sizeof(r)))
			return (0);

		memmove(&r, rdata, sizeof(r));

		return (r);

	case QOP_FD_R:
	case QOP_FD_RW:

		if (qop == QOP_FD_R) {
			log_debug("debug: queue-proc: PROC_QUEUE_MESSAGE_FD_R");
			msg = PROC_QUEUE_MESSAGE_FD_R;
		}
		else {
			log_debug("debug: queue-proc: PROC_QUEUE_MESSAGE_FD_RW");
			msg = PROC_QUEUE_MESSAGE_FD_RW;
		}

		imsg_compose(&ibuf, msg, 0, 0, -1, msgid, sizeof(*msgid));
		if (!queue_proc_call(0))
			return (-1);
		return (imsg.fd);

	default:
		fatalx("queue_proc_message: unsupported operation.");
	}

	return (0);
}

static int
queue_proc_envelope(enum queue_op qop, uint64_t *evpid, char *buf, size_t len)
{
	struct ibuf	*b;
	uint32_t	 msgid;
	int		 r;
	
	if (!running)
		return (0);

	switch (qop) {
	case QOP_CREATE:

		log_debug("debug: queue-proc: PROC_QUEUE_ENVELOPE_CREATE");

		msgid = evpid_to_msgid(*evpid);
		b = imsg_create(&ibuf, PROC_QUEUE_ENVELOPE_CREATE, 0, 0,
		    sizeof(msgid) + len);
		imsg_add(b, &msgid, sizeof(msgid));
		imsg_add(b, buf, len);
		imsg_close(&ibuf, b);

		if (!queue_proc_call(-1))
			return (0);

		if (rlen < sizeof(r)) {
			log_warnx("warn: queue-proc: XXX");
			return (0);
		}

		memmove(&r, rdata, sizeof(r));
		rdata += sizeof(r);
		rlen -= sizeof(r);
		if (r != 1) {
			if (rlen)
				log_warnx("warn: queue-proc: bogus data");
			return (r);
		}
		if (rlen < sizeof(*evpid)) {
			log_warnx("warn: queue-proc: bogus data");
			return (0);
		}

		memmove(evpid, rdata, sizeof(*evpid));
		rdata += sizeof(*evpid);
		rlen -= sizeof(*evpid);
		if (rlen)
			log_warnx("warn: queue-proc: bogus data");
		return (r);

	case QOP_DELETE:

		log_debug("debug: queue-proc: PROC_QUEUE_ENVELOPE_DELETE");

		imsg_compose(&ibuf, PROC_QUEUE_ENVELOPE_DELETE, 0, 0, -1, evpid,
		    sizeof(*evpid));

		if (! queue_proc_call(sizeof(r)))
			return (0);

		memmove(&r, rdata, sizeof(r));

		return (r);

	case QOP_LOAD:

		log_debug("debug: queue-proc: PROC_QUEUE_ENVELOPE_LOAD");

		imsg_compose(&ibuf, PROC_QUEUE_ENVELOPE_LOAD, 0, 0, -1, evpid,
		    sizeof(*evpid));

		if (!queue_proc_call(-1))
			return (0);

		if (rlen > len) {
			log_warnx("warn: queue-proc: buf too small");
			memmove(buf, rdata, len);
		}
		else
			memmove(buf, rdata, rlen);
		return (rlen);

	case QOP_UPDATE:

		log_debug("debug: queue-proc: PROC_QUEUE_ENVELOPE_UPDATE");

		b = imsg_create(&ibuf, PROC_QUEUE_ENVELOPE_UPDATE, 0, 0,
		    len + sizeof(*evpid));
		imsg_add(b, evpid, sizeof(*evpid));
		imsg_add(b, buf, len);
		imsg_close(&ibuf, b);

		if  (!queue_proc_call(sizeof(r)))
			return (0);

		memmove(&r, rdata, sizeof(r));

		return (r);

	case QOP_WALK:

		log_debug("debug: queue-proc: PROC_QUEUE_ENVELOPE_WALK");

		imsg_compose(&ibuf, PROC_QUEUE_ENVELOPE_WALK, 0, 0, -1, NULL, 0);

		if (!queue_proc_call(-1))
			return (0);

		if (rlen < sizeof(r)) {
			log_warnx("warn: queue-proc: XXX");
			return (0);
		}

		memmove(&r, rdata, sizeof(r));
		rdata += sizeof(r);
		rlen -= sizeof(r);
		if (r != 1) {
			if (rlen)
				log_warnx("warn: queue-proc: bogus data");
			return (r);
		}
		if (rlen < sizeof(*evpid)) {
			log_warnx("warn: queue-proc: bogus data");
			return (0);
		}

		memmove(evpid, rdata, sizeof(*evpid));
		rdata += sizeof(*evpid);
		rlen -= sizeof(evpid);
		if (rlen)
			log_warnx("warn: queue-proc: bogus data");
		return (r);

	default:
		log_warnx("warn: queue-proc: unsupported operation.");
		fatalx("queue-proc: exiting");
	}

	return (0);
}

static int
queue_proc_call(size_t expected)
{
	ssize_t	n;

	if (imsg_flush(&ibuf) == -1) {
		log_warn("warn: queue-proc: imsg_flush");
		imsg_clear(&ibuf);
		running = 0;
		return (0);
	}

	while (1) {
		if ((n = imsg_get(&ibuf, &imsg)) == -1) {
			log_warn("warn: queue-proc: imsg_get");
			break;
		}
		if (n) {
			rlen = imsg.hdr.len - IMSG_HEADER_SIZE;
			rdata = imsg.data;

			if (imsg.hdr.type == PROC_QUEUE_OK) {
				if (expected == (size_t)-1 || rlen == expected)
					return (1);
				log_warnx("warn: queue-proc: "
				    "bad msg length (%i/%i)",
				    (int)rlen, (int)expected);
				break;
			}

			log_warn("warn: queue-proc: bad response");
			break;
		}

		if ((n = imsg_read(&ibuf)) == -1) {
			log_warn("warn: queue-proc: imsg_read");
			break;
		}

		if (n == 0) {
			log_warnx("warn: queue-proc: pipe closed");
			break;
		}
	}

	log_warnx("warn: queue-proc: not running anymore");
	imsg_clear(&ibuf);
	running = 0;
	return (0);
}
