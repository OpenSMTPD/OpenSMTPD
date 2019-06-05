/*	$OpenBSD: ioev.c,v 1.41 2017/05/17 14:00:06 deraadt Exp $	*/
/*
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
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifdef IO_TLS
#include <tls.h>
#endif
#include <unistd.h>

#include "ioev2.h"
#include "iobuf2.h"

enum {
	IO_STATE_NONE,
	IO_STATE_CONNECT,
	IO_STATE_CONNECT_SSL,
	IO_STATE_ACCEPT_SSL,
	IO_STATE_UP,

	IO_STATE_MAX,
};

#define IO_PAUSE_IN 		IO_IN
#define IO_PAUSE_OUT		IO_OUT
#define IO_READ			0x04
#define IO_WRITE		0x08
#define IO_RW			(IO_READ | IO_WRITE)
#define IO_RESET		0x10  /* internal */
#define IO_HELD			0x20  /* internal */

struct io {
	int		 sock;
	void		*arg;
	void		(*cb)(struct io*, int, void *);
	struct iobuf	 iobuf;
	size_t		 lowat;
	int		 timeout;
	int		 flags;
	int		 state;
	struct event	 ev;
	void		*tls;
	const char	*error; /* only valid immediately on callback */
};

const char* io2_strflags(int);
const char* io2_evstr(short);

void	_io2_init(void);
void	io2_hold(struct io *);
void	io2_release(struct io *);
void	io2_callback(struct io*, int);
void	io2_dispatch(int, short, void *);
void	io2_dispatch_connect(int, short, void *);
size_t	io2_pending(struct io *);
size_t	io2_queued(struct io*);
void	io2_reset(struct io *, short, void (*)(int, short, void*));
void	io2_frame_enter(const char *, struct io *, int);
void	io2_frame_leave(struct io *);

#ifdef IO_TLS
void	io2_dispatch_accept_tls(int, short, void *);
void	io2_dispatch_connect_tls(int, short, void *);
void	io2_dispatch_read_tls(int, short, void *);
void	io2_dispatch_write_tls(int, short, void *);
void	io2_reload_tls(struct io *io);
#endif

static struct io	*current = NULL;
static uint64_t		 frame = 0;
static int		_io2_debug = 0;

#define io2_debug(args...) do { if (_io2_debug) printf(args); } while(0)


const char*
io2_strio(struct io *io)
{
	static char	buf[128];
	char		ssl[128];

	ssl[0] = '\0';
#ifdef IO_TLS
	if (io->tls) {
//		(void)snprintf(ssl, sizeof ssl, " ssl=%s:%s:%d",
//		    SSL_get_version(io->tls),
//		    SSL_get_cipher_name(io->tls),
//		    SSL_get_cipher_bits(io->tls, NULL));
	}
#endif

	(void)snprintf(buf, sizeof buf,
	    "<io:%p fd=%d to=%d fl=%s%s ib=%zu ob=%zu>",
	    io, io->sock, io->timeout, io2_strflags(io->flags), ssl,
	    io2_pending(io), io2_queued(io));

	return (buf);
}

#define CASE(x) case x : return #x

const char*
io2_strevent(int evt)
{
	static char buf[32];

	switch (evt) {
	CASE(IO_CONNECTED);
	CASE(IO_TLSREADY);
	CASE(IO_DATAIN);
	CASE(IO_LOWAT);
	CASE(IO_DISCONNECTED);
	CASE(IO_TIMEOUT);
	CASE(IO_ERROR);
	default:
		(void)snprintf(buf, sizeof(buf), "IO_? %d", evt);
		return buf;
	}
}

void
io2_set_nonblocking(int fd)
{
	int	flags;

	if ((flags = fcntl(fd, F_GETFL)) == -1)
		err(1, "io2_set_blocking:fcntl(F_GETFL)");

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1)
		err(1, "io2_set_blocking:fcntl(F_SETFL)");
}

void
io2_set_nolinger(int fd)
{
	struct linger    l;

	memset(&l, 0, sizeof(l));
	if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l)) == -1)
		err(1, "io2_set_linger:setsockopt()");
}

/*
 * Event framing must not rely on an io pointer to refer to the "same" io
 * throughout the frame, because this is not always the case:
 *
 * 1) enter(addr0) -> free(addr0) -> leave(addr0) = SEGV
 * 2) enter(addr0) -> free(addr0) -> malloc == addr0 -> leave(addr0) = BAD!
 *
 * In both case, the problem is that the io is freed in the callback, so
 * the pointer becomes invalid. If that happens, the user is required to
 * call io2_clear, so we can adapt the frame state there.
 */
void
io2_frame_enter(const char *where, struct io *io, int ev)
{
	io2_debug("\n=== %" PRIu64 " ===\n"
	    "io2_frame_enter(%s, %s, %s)\n",
	    frame, where, io2_evstr(ev), io2_strio(io));

	if (current)
		errx(1, "io2_frame_enter: interleaved frames");

	current = io;

	io2_hold(io);
}

void
io2_frame_leave(struct io *io)
{
	io2_debug("io2_frame_leave(%" PRIu64 ")\n", frame);

	if (current && current != io)
		errx(1, "io2_frame_leave: io mismatch");

	/* io has been cleared */
	if (current == NULL)
		goto done;

	/* TODO: There is a possible optimization there:
	 * In a typical half-duplex request/response scenario,
	 * the io is waiting to read a request, and when done, it queues
	 * the response in the output buffer and goes to write mode.
	 * There, the write event is set and will be triggered in the next
	 * event frame.  In most case, the write call could be done
	 * immediately as part of the last read frame, thus avoiding to go
	 * through the event loop machinery. So, as an optimisation, we
	 * could detect that case here and force an event dispatching.
	 */

	/* Reload the io if it has not been reset already. */
	io2_release(io);
	current = NULL;
    done:
	io2_debug("=== /%" PRIu64 "\n", frame);

	frame += 1;
}

void
_io2_init()
{
	static int init = 0;

	if (init)
		return;

	init = 1;
	_io2_debug = getenv("IO_DEBUG") != NULL;
}

struct io *
io2_new(void)
{
	struct io *io;

	_io2_init();

	if ((io = calloc(1, sizeof(*io))) == NULL)
		return NULL;

	io->sock = -1;
	io->timeout = -1;

	if (iobuf2_init(&io->iobuf, 0, 0) == -1) {
		free(io);
		return NULL;
	}

	return io;
}

void
io2_free(struct io *io)
{
	io2_debug("io2_clear(%p)\n", io);

	/* the current io is virtually dead */
	if (io == current)
		current = NULL;

#ifdef IO_TLS
	tls_free(io->tls);
	io->tls = NULL;
#endif

	if (event_initialized(&io->ev))
		event_del(&io->ev);
	if (io->sock != -1) {
		close(io->sock);
		io->sock = -1;
	}

	iobuf2_clear(&io->iobuf);
	free(io);
}

void
io2_hold(struct io *io)
{
	io2_debug("io2_enter(%p)\n", io);

	if (io->flags & IO_HELD)
		errx(1, "io2_hold: io is already held");

	io->flags &= ~IO_RESET;
	io->flags |= IO_HELD;
}

void
io2_release(struct io *io)
{
	if (!(io->flags & IO_HELD))
		errx(1, "io2_release: io is not held");

	io->flags &= ~IO_HELD;
	if (!(io->flags & IO_RESET))
		io2_reload(io);
}

void
io2_set_fd(struct io *io, int fd)
{
	io->sock = fd;
	if (fd != -1)
		io2_reload(io);
}

void
io2_set_callback(struct io *io, void(*cb)(struct io *, int, void *), void *arg)
{
	io->cb = cb;
	io->arg = arg;
}

void
io2_set_timeout(struct io *io, int msec)
{
	io2_debug("io2_set_timeout(%p, %d)\n", io, msec);

	io->timeout = msec;
}

void
io2_set_lowat(struct io *io, size_t lowat)
{
	io2_debug("io2_set_lowat(%p, %zu)\n", io, lowat);

	io->lowat = lowat;
}

void
io2_pause(struct io *io, int dir)
{
	io2_debug("io2_pause(%p, %x)\n", io, dir);

	io->flags |= dir & (IO_PAUSE_IN | IO_PAUSE_OUT);
	io2_reload(io);
}

void
io2_resume(struct io *io, int dir)
{
	io2_debug("io2_resume(%p, %x)\n", io, dir);

	io->flags &= ~(dir & (IO_PAUSE_IN | IO_PAUSE_OUT));
	io2_reload(io);
}

void
io2_set_read(struct io *io)
{
	int	mode;

	io2_debug("io2_set_read(%p)\n", io);

	mode = io->flags & IO_RW;
	if (!(mode == 0 || mode == IO_WRITE))
		errx(1, "io2_set_read(): full-duplex or reading");

	io->flags &= ~IO_RW;
	io->flags |= IO_READ;
	io2_reload(io);
}

void
io2_set_write(struct io *io)
{
	int	mode;

	io2_debug("io2_set_write(%p)\n", io);

	mode = io->flags & IO_RW;
	if (!(mode == 0 || mode == IO_READ))
		errx(1, "io2_set_write(): full-duplex or writing");

	io->flags &= ~IO_RW;
	io->flags |= IO_WRITE;
	io2_reload(io);
}

const char *
io2_error(struct io *io)
{
	return io->error;
}

void *
io2_tls(struct io *io)
{
	return io->tls;
}

int
io2_fileno(struct io *io)
{
	return io->sock;
}

int
io2_paused(struct io *io, int what)
{
	return (io->flags & (IO_PAUSE_IN | IO_PAUSE_OUT)) == what;
}

/*
 * Buffered output functions
 */

int
io2_write(struct io *io, const void *buf, size_t len)
{
	int r;

	r = iobuf2_queue(&io->iobuf, buf, len);

	io2_reload(io);

	return r;
}

int
io2_writev(struct io *io, const struct iovec *iov, int iovcount)
{
	int r;

	r = iobuf2_queuev(&io->iobuf, iov, iovcount);

	io2_reload(io);

	return r;
}

int
io2_print(struct io *io, const char *s)
{
	return io2_write(io, s, strlen(s));
}

int
io2_printf(struct io *io, const char *fmt, ...)
{
	va_list ap;
	int r;

	va_start(ap, fmt);
	r = io2_vprintf(io, fmt, ap);
	va_end(ap);

	return r;
}

int
io2_vprintf(struct io *io, const char *fmt, va_list ap)
{

	char *buf;
	int len;

	len = vasprintf(&buf, fmt, ap);
	if (len == -1)
		return -1;
	len = io2_write(io, buf, len);
	free(buf);

	return len;
}

size_t
io2_queued(struct io *io)
{
	return iobuf2_queued(&io->iobuf);
}

/*
 * Buffered input functions
 */

void *
io2_data(struct io *io)
{
	return iobuf2_data(&io->iobuf);
}

size_t
io2_datalen(struct io *io)
{
	return iobuf2_len(&io->iobuf);
}

char *
io2_getline(struct io *io, size_t *sz)
{
	return iobuf2_getline(&io->iobuf, sz);
}

void
io2_drop(struct io *io, size_t sz)
{
	return iobuf2_drop(&io->iobuf, sz);
}


#define IO_READING(io) (((io)->flags & IO_RW) != IO_WRITE)
#define IO_WRITING(io) (((io)->flags & IO_RW) != IO_READ)

/*
 * Setup the necessary events as required by the current io state,
 * honouring duplex mode and i/o pauses.
 */
void
io2_reload(struct io *io)
{
	short	events;

	/* io will be reloaded at release time */
	if (io->flags & IO_HELD)
		return;

	iobuf2_normalize(&io->iobuf);

#ifdef IO_TLS
	if (io->tls) {
		io2_reload_tls(io);
		return;
	}
#endif

	io2_debug("io2_reload(%p)\n", io);

	events = 0;
	if (IO_READING(io) && !(io->flags & IO_PAUSE_IN))
		events = EV_READ;
	if (IO_WRITING(io) && !(io->flags & IO_PAUSE_OUT) && io2_queued(io))
		events |= EV_WRITE;

	io2_reset(io, events, io2_dispatch);
}

/* Set the requested event. */
void
io2_reset(struct io *io, short events, void (*dispatch)(int, short, void*))
{
	struct timeval	tv, *ptv;

	io2_debug("io2_reset(%p, %s, %p) -> %s\n",
	    io, io2_evstr(events), dispatch, io2_strio(io));

	/*
	 * Indicate that the event has already been reset so that reload
	 * is not called on frame_leave.
	 */
	io->flags |= IO_RESET;

	if (event_initialized(&io->ev))
		event_del(&io->ev);

	/*
	 * The io is paused by the user, so we don't want the timeout to be
	 * effective.
	 */
	if (events == 0)
		return;

	event_set(&io->ev, io->sock, events, dispatch, io);
	if (io->timeout >= 0) {
		tv.tv_sec = io->timeout / 1000;
		tv.tv_usec = (io->timeout % 1000) * 1000;
		ptv = &tv;
	} else
		ptv = NULL;

	event_add(&io->ev, ptv);
}

size_t
io2_pending(struct io *io)
{
	return iobuf2_len(&io->iobuf);
}

const char*
io2_strflags(int flags)
{
	static char	buf[64];

	buf[0] = '\0';

	switch (flags & IO_RW) {
	case 0:
		(void)strlcat(buf, "rw", sizeof buf);
		break;
	case IO_READ:
		(void)strlcat(buf, "R", sizeof buf);
		break;
	case IO_WRITE:
		(void)strlcat(buf, "W", sizeof buf);
		break;
	case IO_RW:
		(void)strlcat(buf, "RW", sizeof buf);
		break;
	}

	if (flags & IO_PAUSE_IN)
		(void)strlcat(buf, ",F_PI", sizeof buf);
	if (flags & IO_PAUSE_OUT)
		(void)strlcat(buf, ",F_PO", sizeof buf);

	return buf;
}

const char*
io2_evstr(short ev)
{
	static char	buf[64];
	char		buf2[16];
	int		n;

	n = 0;
	buf[0] = '\0';

	if (ev == 0) {
		(void)strlcat(buf, "<NONE>", sizeof(buf));
		return buf;
	}

	if (ev & EV_TIMEOUT) {
		(void)strlcat(buf, "EV_TIMEOUT", sizeof(buf));
		ev &= ~EV_TIMEOUT;
		n++;
	}

	if (ev & EV_READ) {
		if (n)
			(void)strlcat(buf, "|", sizeof(buf));
		(void)strlcat(buf, "EV_READ", sizeof(buf));
		ev &= ~EV_READ;
		n++;
	}

	if (ev & EV_WRITE) {
		if (n)
			(void)strlcat(buf, "|", sizeof(buf));
		(void)strlcat(buf, "EV_WRITE", sizeof(buf));
		ev &= ~EV_WRITE;
		n++;
	}

	if (ev & EV_SIGNAL) {
		if (n)
			(void)strlcat(buf, "|", sizeof(buf));
		(void)strlcat(buf, "EV_SIGNAL", sizeof(buf));
		ev &= ~EV_SIGNAL;
		n++;
	}

	if (ev) {
		if (n)
			(void)strlcat(buf, "|", sizeof(buf));
		(void)strlcat(buf, "EV_?=0x", sizeof(buf));
		(void)snprintf(buf2, sizeof(buf2), "%hx", ev);
		(void)strlcat(buf, buf2, sizeof(buf));
	}

	return buf;
}

void
io2_dispatch(int fd, short ev, void *humppa)
{
	struct io	*io = humppa;
	size_t		 w;
	ssize_t		 n;
	int		 saved_errno;

	io2_frame_enter("io2_dispatch", io, ev);

	if (ev == EV_TIMEOUT) {
		io2_callback(io, IO_TIMEOUT);
		goto leave;
	}

	if (ev & EV_WRITE && (w = io2_queued(io))) {
		if ((n = iobuf2_write(&io->iobuf, io->sock)) < 0) {
			if (n == IOBUF_WANT_WRITE) /* kqueue bug? */
				goto read;
			if (n == IOBUF_CLOSED)
				io2_callback(io, IO_DISCONNECTED);
			else {
				saved_errno = errno;
				io->error = strerror(errno);
				errno = saved_errno;
				io2_callback(io, IO_ERROR);
			}
			goto leave;
		}
		if (w > io->lowat && w - n <= io->lowat)
			io2_callback(io, IO_LOWAT);
	}
    read:

	if (ev & EV_READ) {
		iobuf2_normalize(&io->iobuf);
		if ((n = iobuf2_read(&io->iobuf, io->sock)) < 0) {
			if (n == IOBUF_CLOSED)
				io2_callback(io, IO_DISCONNECTED);
			else {
				saved_errno = errno;
				io->error = strerror(errno);
				errno = saved_errno;
				io2_callback(io, IO_ERROR);
			}
			goto leave;
		}
		if (n)
			io2_callback(io, IO_DATAIN);
	}

leave:
	io2_frame_leave(io);
}

void
io2_callback(struct io *io, int evt)
{
	io->cb(io, evt, io->arg);
}

int
io2_connect(struct io *io, const struct sockaddr *sa, const struct sockaddr *bsa)
{
	int	sock, errno_save;

	if ((sock = socket(sa->sa_family, SOCK_STREAM, 0)) == -1)
		goto fail;

	io2_set_nonblocking(sock);
	io2_set_nolinger(sock);

	if (bsa && bind(sock, bsa, bsa->sa_len) == -1)
		goto fail;

	if (connect(sock, sa, sa->sa_len) == -1)
		if (errno != EINPROGRESS)
			goto fail;

	io->sock = sock;
	io2_reset(io, EV_WRITE, io2_dispatch_connect);

	return (sock);

    fail:
	if (sock != -1) {
		errno_save = errno;
		close(sock);
		errno = errno_save;
		io->error = strerror(errno);
	}
	return (-1);
}

void
io2_dispatch_connect(int fd, short ev, void *humppa)
{
	struct io	*io = humppa;
	int		 r, e;
	socklen_t	 sl;

	io2_frame_enter("io2_dispatch_connect", io, ev);

	if (ev == EV_TIMEOUT) {
		close(fd);
		io->sock = -1;
		io2_callback(io, IO_TIMEOUT);
	} else {
		sl = sizeof(e);
		r = getsockopt(fd, SOL_SOCKET, SO_ERROR, &e, &sl);
		if (r == -1)  {
			warn("io2_dispatch_connect: getsockopt");
			e = errno;
		}
		if (e) {
			close(fd);
			io->sock = -1;
			io->error = strerror(e);
			io2_callback(io, e == ETIMEDOUT ? IO_TIMEOUT : IO_ERROR);
		}
		else {
			io->state = IO_STATE_UP;
			io2_callback(io, IO_CONNECTED);
		}
	}

	io2_frame_leave(io);
}

#ifdef IO_TLS
int
io2_start_tls(struct io *io, void *tls)
{
	int	mode;

	mode = io->flags & IO_RW;
	if (mode == 0 || mode == IO_RW)
		errx(1, "io2_start_tls(): full-duplex or unset");

	if (io->tls)
		errx(1, "io2_start_tls(): SSL already started");
	io->tls = tls;

	//if (SSL_set_fd(io->tls, io->sock) == 0) {
	//	return (-1);
	//}

	if (mode == IO_WRITE) {
		io->state = IO_STATE_CONNECT_SSL;
		io2_reset(io, EV_WRITE, io2_dispatch_connect_tls);
	} else {
		io->state = IO_STATE_ACCEPT_SSL;
		io2_reset(io, EV_READ, io2_dispatch_accept_tls);
	}

	return (0);
}

void
io2_dispatch_accept_tls(int fd, short event, void *humppa)
{
/*
	struct io	*io = humppa;
	int		 ret;

	io2_frame_enter("io2_dispatch_accept_tls", io, event);

	if (event == EV_TIMEOUT) {
		io2_callback(io, IO_TIMEOUT);
		goto leave;
	}

	if ((ret = SSL_accept(io->tls)) > 0) {
		io->state = IO_STATE_UP;
		io2_callback(io, IO_TLSREADY);
		goto leave;
	}

	switch ((e = SSL_get_error(io->tls, ret))) {
	case SSL_ERROR_WANT_READ:
		io2_reset(io, EV_READ, io2_dispatch_accept_tls);
		break;
	case SSL_ERROR_WANT_WRITE:
		io2_reset(io, EV_WRITE, io2_dispatch_accept_tls);
		break;
	default:
		io->error = tls_error(io->tls);
		io2_callback(io, IO_ERROR);
		break;
	}

    leave:
	io2_frame_leave(io);
*/
	return;
}

void
io2_dispatch_connect_tls(int fd, short event, void *humppa)
{
	struct io	*io = humppa;
	int		 ret;

	io2_frame_enter("io2_dispatch_connect_tls", io, event);

	if (event == EV_TIMEOUT) {
		io2_callback(io, IO_TIMEOUT);
		goto leave;
	}

	if ((ret = tls_connect_socket(io->tls, io->sock, NULL)) > 0) {
		io->state = IO_STATE_UP;
		io2_callback(io, IO_TLSREADY);
		goto leave;
	}

	if (ret == TLS_WANT_POLLIN)
		io2_reset(io, EV_READ, io2_dispatch_connect_tls);
	else if (ret == TLS_WANT_POLLOUT)
		io2_reset(io, EV_WRITE, io2_dispatch_connect_tls);
	else
		io->error = tls_error(io->tls);
		io2_callback(io, IO_TLSERROR);

    leave:
	io2_frame_leave(io);
}

void
io2_dispatch_read_tls(int fd, short event, void *humppa)
{
	struct io	*io = humppa;
	int		 n, saved_errno;

	io2_frame_enter("io2_dispatch_read_tls", io, event);

	if (event == EV_TIMEOUT) {
		io2_callback(io, IO_TIMEOUT);
		goto leave;
	}

again:
	iobuf2_normalize(&io->iobuf);
	switch ((n = iobuf2_read_tls(&io->iobuf, io->tls))) {
	case IOBUF_WANT_READ:
		io2_reset(io, EV_READ, io2_dispatch_read_tls);
		break;
	case IOBUF_WANT_WRITE:
		io2_reset(io, EV_WRITE, io2_dispatch_read_tls);
		break;
	case IOBUF_CLOSED:
		io2_callback(io, IO_DISCONNECTED);
		break;
	case IOBUF_ERROR:
		saved_errno = errno;
		io->error = strerror(errno);
		errno = saved_errno;
		io2_callback(io, IO_ERROR);
		break;
	case IOBUF_SSLERROR:
		io->error = tls_error(io->tls);
		io2_callback(io, IO_ERROR);
		break;
	default:
		io2_debug("io2_dispatch_read_tls(...) -> r=%d\n", n);
		io2_callback(io, IO_DATAIN);
		if (current == io && IO_READING(io))
			goto again;
	}

    leave:
	io2_frame_leave(io);
}

void
io2_dispatch_write_tls(int fd, short event, void *humppa)
{
	struct io	*io = humppa;
	int		 n, saved_errno;
	size_t		 w2, w;

	io2_frame_enter("io2_dispatch_write_tls", io, event);

	if (event == EV_TIMEOUT) {
		io2_callback(io, IO_TIMEOUT);
		goto leave;
	}

	w = io2_queued(io);
	switch ((n = iobuf2_write_tls(&io->iobuf, io->tls))) {
	case IOBUF_WANT_READ:
		io2_reset(io, EV_READ, io2_dispatch_write_tls);
		break;
	case IOBUF_WANT_WRITE:
		io2_reset(io, EV_WRITE, io2_dispatch_write_tls);
		break;
	case IOBUF_CLOSED:
		io2_callback(io, IO_DISCONNECTED);
		break;
	case IOBUF_ERROR:
		saved_errno = errno;
		io->error = strerror(errno);
		errno = saved_errno;
		io2_callback(io, IO_ERROR);
		break;
	case IOBUF_SSLERROR:
		io->error = tls_error(io->tls);
		io2_callback(io, IO_ERROR);
		break;
	default:
		io2_debug("io2_dispatch_write_tls(...) -> w=%d\n", n);
		w2 = io2_queued(io);
		if (w > io->lowat && w2 <= io->lowat)
			io2_callback(io, IO_LOWAT);
		break;
	}

    leave:
	io2_frame_leave(io);
}

void
io2_reload_tls(struct io *io)
{
	short	ev = 0;
	void	(*dispatch)(int, short, void*) = NULL;

	switch (io->state) {
	case IO_STATE_CONNECT_SSL:
		ev = EV_WRITE;
		dispatch = io2_dispatch_connect_tls;
		break;
	case IO_STATE_ACCEPT_SSL:
		ev = EV_READ;
		dispatch = io2_dispatch_accept_tls;
		break;
	case IO_STATE_UP:
		ev = 0;
		if (IO_READING(io) && !(io->flags & IO_PAUSE_IN)) {
			ev = EV_READ;
			dispatch = io2_dispatch_read_tls;
		}
		else if (IO_WRITING(io) && !(io->flags & IO_PAUSE_OUT) &&
		    io2_queued(io)) {
			ev = EV_WRITE;
			dispatch = io2_dispatch_write_tls;
		}
		if (!ev)
			return; /* paused */
		break;
	default:
		errx(1, "io2_reload_tls(): bad state");
	}

	io2_reset(io, ev, dispatch);
}

#endif /* IO_TLS */
