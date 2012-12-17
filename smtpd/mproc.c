/*	$OpenBSD: dns.c,v 1.61 2012/11/12 14:58:53 eric Exp $	*/

/*
 * Copyright (c) 2012 Eric Faurot <eric@faurot.net>
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
#include <sys-tree.h>
#include <sys-queue.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <event.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd.h"
#include "log.h"

static void mproc_dispatch(int, short, void *);
static void mproc_event_add(struct mproc *);

void
mproc_init(struct mproc *p, int fd)
{
	imsg_init(&p->imsgbuf, fd);
}

void
mproc_clear(struct mproc *p)
{
	event_del(&p->ev);
	close(p->imsgbuf.fd);
	imsg_clear(&p->imsgbuf);
}

void
mproc_enable(struct mproc *p)
{
	if (p->enable)
		return;
	p->enable = 1;
	mproc_event_add(p);
}

void
mproc_disable(struct mproc *p)
{
	if (p->enable == 0)
		return;
	p->enable = 0;
	event_del(&p->ev);
}

void
m_forward(struct mproc *p, struct imsg *imsg)
{
	imsg_compose(&p->imsgbuf, imsg->hdr.type, imsg->hdr.peerid,
	    imsg->hdr.pid, imsg->fd, imsg->data,
	    imsg->hdr.len - sizeof(imsg->hdr));
	mproc_event_add(p);
}

void
m_compose(struct mproc *p, uint32_t type, uint32_t peerid, pid_t pid, int fd,
    void *data, size_t len)
{
	imsg_compose(&p->imsgbuf, type, peerid, pid, fd, data, len);
	mproc_event_add(p);
}

void m_composev(struct mproc *p, uint32_t type, uint32_t peerid, pid_t pid,
    int fd, const struct iovec *iov, int n)
{
	imsg_composev(&p->imsgbuf, type, peerid, pid, fd, iov, n);
	mproc_event_add(p);
}

void
m_create(struct mproc *p, uint32_t type, uint32_t peerid, pid_t pid, int fd,
    size_t len)
{
	if (p->ibuf)
		fatal("ibuf already rhere");

	p->ibuf = imsg_create(&p->imsgbuf, type, peerid, pid, fd);
	if (p->ibuf == NULL)
		fatal("imsg_create");
}

void
m_add(struct mproc *p, const void *data, size_t len)
{
	if (p->ibuferror)
		return;

	if (ibuf_add(p->ibuf, data, len) == -1)
		p->ibuferror = 1;
}

void
m_close(struct mproc *p)
{
	imsg_close(&p->imsgbuf, p->ibuf);
	p->ibuf = NULL;
	mproc_event_add(p);
}

static void
mproc_event_add(struct mproc *p)
{
	short	events;

	if (p->enable == 0)
		return;

	events = EV_READ;
	if (p->imsgbuf.w.queued)
		events |= EV_WRITE;

	event_del(&p->ev);
	event_set(&p->ev, p->imsgbuf.fd, events, mproc_dispatch, p);
	event_add(&p->ev, NULL);
}

static void
mproc_dispatch(int fd, short event, void *arg)
{
	struct mproc	*p = arg;
	struct imsg	 imsg;
	ssize_t		 n;

	if (event & EV_READ) {

		if (p->enable == 0) {
			log_warn("%s <=> %s not enabled!",
			    proc_to_str(smtpd_process), p->name);
			fatal("nga");
		}

		if ((n = imsg_read(&p->imsgbuf)) == -1)
			fatal("imsg_read");
		if (n == 0) {
			/* this pipe is dead, so remove the event handler */
			p->handler(p, NULL);
			return;
		}
	}

	if (event & EV_WRITE) {
		if (msgbuf_write(&p->imsgbuf.w) == -1)
			fatal("msgbuf_write");
	}

	for (;;) {
		if ((n = imsg_get(&p->imsgbuf, &imsg)) == -1)
			fatal("imsg_get");
		if (n == 0)
			break;

		p->handler(p, &imsg);

		imsg_free(&imsg);
	}
	mproc_event_add(p);
}
