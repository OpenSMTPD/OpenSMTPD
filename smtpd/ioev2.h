/*	$OpenBSD: ioev.h,v 1.16 2016/11/30 17:43:32 eric Exp $	*/
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

enum {
	IO2_CONNECTED = 0, 	/* connection successful	*/
	IO2_TLSREADY,		/* TLS started successfully	*/
	IO2_TLSERROR,		/* XXX - needs more work	*/
	IO2_DATAIN,		/* new data in input buffer	*/
	IO2_LOWAT,		/* output queue running low	*/
	IO2_DISCONNECTED,	/* error?			*/
	IO2_TIMEOUT,		/* error?			*/
	IO2_ERROR,		/* details?			*/
};

#define IO2_IN		0x01
#define IO2_OUT		0x02

struct io;

void io2_set_nonblocking(int);
void io2_set_nolinger(int);

struct io *io2_new(void);
void io2_free(struct io *);
void io2_set_read(struct io *);
void io2_set_write(struct io *);
void io2_set_fd(struct io *, int);
void io2_set_callback(struct io *io, void(*)(struct io *, int, void *), void *);
void io2_set_timeout(struct io *, int);
void io2_set_lowat(struct io *, size_t);
void io2_pause(struct io *, int);
void io2_resume(struct io *, int);
void io2_reload(struct io *);
int io2_connect(struct io *, const struct sockaddr *, const struct sockaddr *);
int io2_start_tls(struct io *, void *);
const char* io2_strio(struct io *);
const char* io2_strevent(int);
const char* io2_error(struct io *);
void* io2_tls(struct io *);
int io2_fileno(struct io *);
int io2_paused(struct io *, int);

/* Buffered output functions */
int io2_write(struct io *, const void *, size_t);
int io2_writev(struct io *, const struct iovec *, int);
int io2_print(struct io *, const char *);
int io2_printf(struct io *, const char *, ...);
int io2_vprintf(struct io *, const char *, va_list);
size_t io2_queued(struct io *);

/* Buffered input functions */
void* io2_data(struct io *);
size_t io2_datalen(struct io *);
char* io2_getline(struct io *, size_t *);
void io2_drop(struct io *, size_t);
