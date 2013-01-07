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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/tree.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <err.h>
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

int
mproc_fork(struct mproc *p, const char *path, const char *arg)
{
	int sp[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, sp) < 0)
		return (-1);

	session_socket_blockmode(sp[0], BM_NONBLOCK);
	session_socket_blockmode(sp[1], BM_NONBLOCK);

	if ((p->pid = fork()) == -1)
		goto err;

	if (p->pid == 0) {
		/* child process */
		dup2(sp[0], STDIN_FILENO);
		if (closefrom(STDERR_FILENO + 1) < 0)
			exit(1);

		execl(path, arg, NULL);
		err(1, "execl");
	}

	/* parent process */
	close(sp[0]);
	mproc_init(p, sp[1]);
	return (0);

err:
	log_warn("warn: Failed to start process %s, instance of %s", arg, path);
	close(sp[0]);
	close(sp[1]);
	return (-1);
}

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

void
m_composev(struct mproc *p, uint32_t type, uint32_t peerid, pid_t pid,
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

void
m_msg(struct msg *m, struct imsg *imsg)
{
	m->pos = imsg->data;
	m->end = m->pos + (imsg->hdr.len - sizeof(imsg->hdr));
}

void
m_end(struct msg *m)
{
	if (m->pos != m->end)
		fatalx("not at msg end");
}

int
m_is_eom(struct msg *m)
{
	return (m->pos == m->end);
}

static inline void
m_get(struct msg *m, void *dst, size_t sz)
{
	if (m->pos + sz > m->end)
		fatalx("msg too short");
	memmove(dst, m->pos, sz);
	m->pos += sz;
}

static inline void
m_get_typed(struct msg *m, uint8_t type, void *dst, size_t sz)
{
	if (m->pos + 1 + sz > m->end)
		fatalx("msg too short");
	if (*m->pos != type)
		fatalx("msg bad type");
	memmove(dst, m->pos + 1, sz);
	m->pos += sz + 1;
}

static inline void
m_get_typed_sized(struct msg *m, uint8_t type, const void **dst, size_t *sz)
{
	if (m->pos + 1 + sizeof(*sz) > m->end)
		fatalx("msg too short");
	if (*m->pos != type)
		fatalx("msg bad type");
	memmove(sz, m->pos + 1, sizeof(*sz));
	m->pos += sizeof(sz) + 1;
	if (m->pos + *sz > m->end)
		fatalx("msg too short");
	*dst = m->pos;
	m->pos += *sz;
}

static void
m_add_typed(struct mproc *p, uint8_t type, const void *data, size_t len)
{
	if (p->ibuferror)
		return;

	if (ibuf_add(p->ibuf, &type, 1) == -1 ||
	    ibuf_add(p->ibuf, data, len) == -1)
		p->ibuferror = 1;
}

static void
m_add_typed_sized(struct mproc *p, uint8_t type, const void *data, size_t len)
{
	if (p->ibuferror)
		return;

	if (ibuf_add(p->ibuf, &type, 1) == -1 ||
	    ibuf_add(p->ibuf, &len, sizeof(len)) == -1 ||
	    ibuf_add(p->ibuf, data, len) == -1)
		p->ibuferror = 1;
}

enum {
	M_INT,
	M_UINT32,
	M_TIME,
	M_STRING,
	M_DATA,
	M_ID,
	M_EVPID,
	M_MSGID,
	M_SOCKADDR,
	M_MAILADDR,
	M_ENVELOPE,
};

void
m_add_int(struct mproc *m, int v)
{
	m_add_typed(m, M_INT, &v, sizeof v);
};

void
m_add_u32(struct mproc *m, uint32_t u32)
{
	m_add_typed(m, M_UINT32, &u32, sizeof u32);
};

void
m_add_time(struct mproc *m, time_t v)
{
	m_add_typed(m, M_TIME, &v, sizeof v);
};

void
m_add_string(struct mproc *m, const char *v)
{
	m_add_typed(m, M_STRING, v, strlen(v) + 1);
};

void
m_add_data(struct mproc *m, const void *v, size_t len)
{
	m_add_typed_sized(m, M_DATA, v, len);
};

void
m_add_id(struct mproc *m, uint64_t v)
{
	m_add_typed(m, M_ID, &v, sizeof(v));
}

void
m_add_evpid(struct mproc *m, uint64_t v)
{
	m_add_typed(m, M_EVPID, &v, sizeof(v));
}

void
m_add_msgid(struct mproc *m, uint32_t v)
{
	m_add_typed(m, M_MSGID, &v, sizeof(v));
}

void
m_add_sockaddr(struct mproc *m, const struct sockaddr *sa)
{
	m_add_typed_sized(m, M_SOCKADDR, sa, sa->sa_len);
}

void
m_add_mailaddr(struct mproc *m, const struct mailaddr *maddr)
{
	m_add_typed(m, M_MAILADDR, maddr, sizeof(*maddr));
}

void
m_add_envelope(struct mproc *m, const struct envelope *evp)
{
	m_add_typed(m, M_ENVELOPE, evp, sizeof(*evp));
}

void
m_get_int(struct msg *m, int *i)
{
	m_get_typed(m, M_INT, i, sizeof(*i));
}

void
m_get_u32(struct msg *m, uint32_t *u32)
{
	m_get_typed(m, M_UINT32, u32, sizeof(*u32));
}

void
m_get_time(struct msg *m, time_t *t)
{
	m_get_typed(m, M_TIME, t, sizeof(*t));
}

void
m_get_string(struct msg *m, const char **s)
{
	uint8_t	*end;

	if (m->pos + 2 > m->end)
		fatalx("msg too short");
	if (*m->pos != M_STRING)
		fatalx("bad msg type");

	end = memchr(m->pos + 1, 0, m->end - (m->pos + 1));
	if (end == NULL)
		fatalx("unterminated string");
	
	*s = m->pos + 1;
	m->pos = end + 1;
}

void
m_get_data(struct msg *m, const void **data, size_t *sz)
{
	m_get_typed_sized(m, M_DATA, data, sz);
}

void
m_get_evpid(struct msg *m, uint64_t *evpid)
{
	m_get_typed(m, M_EVPID, evpid, sizeof(*evpid));
}

void
m_get_msgid(struct msg *m, uint32_t *msgid)
{
	m_get_typed(m, M_MSGID, msgid, sizeof(*msgid));
}

void
m_get_id(struct msg *m, uint64_t *id)
{
	m_get_typed(m, M_ID, id, sizeof(*id));
}

void
m_get_sockaddr(struct msg *m, struct sockaddr *sa)
{
	size_t		 s;
	const void	*d;

	m_get_typed_sized(m, M_SOCKADDR, &d, &s);
	memmove(sa, d, s);
}

void
m_get_mailaddr(struct msg *m, struct mailaddr *maddr)
{
	m_get_typed(m, M_MAILADDR, maddr, sizeof(*maddr));
}

void
m_get_envelope(struct msg *m, struct envelope *evp)
{
	m_get_typed(m, M_ENVELOPE, evp, sizeof(*evp));
}

