/*	$OpenBSD: filter_api.c,v 1.4 2012/08/19 14:16:58 chl Exp $	*/

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
#include <sys/uio.h>

#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

int (*handler_message_create)(uint32_t *);
int (*handler_message_commit)(uint32_t);
int (*handler_message_delete)(uint32_t);
int (*handler_message_fd_r)(uint32_t);
int (*handler_message_fd_w)(uint32_t);
int (*handler_message_corrupt)(uint32_t);
int (*handler_envelope_create)(uint32_t, const char *, size_t, uint64_t *);
int (*handler_envelope_delete)(uint64_t);
int (*handler_envelope_update)(uint64_t, const char *, size_t);
int (*handler_envelope_load)(uint64_t, char *, size_t);
int (*handler_envelope_walk)(uint64_t *);

static struct imsgbuf	ibuf;
static struct imsg	imsg;

static int
dispatch(void)
{
	struct ibuf	*buf;
	uint64_t	 evpid;
	uint32_t	 msgid, version;
	size_t		 len;
	char		*data, buffer[8192];
	int		 r, fd;

	data = imsg.data;
	len = imsg.hdr.len - IMSG_HEADER_SIZE;

	switch (imsg.hdr.type) {
	case PROC_QUEUE_INIT:
		if (len != sizeof(version)) {
			log_warnx("warn: queue-api: bad message length");
			goto fail;
		}
		memmove(&version, data, len);
		if (version != PROC_QUEUE_API_VERSION) {
			log_warnx("warn: queue-api: bad API version");
			goto fail;
		}
		imsg_compose(&ibuf, PROC_QUEUE_OK, 0, 0, -1, NULL, 0);
		break;

	case PROC_QUEUE_MESSAGE_CREATE:
		if (len != 0) {
			log_warnx("warn: queue-api: bad message length");
			goto fail;
		}

		r = handler_message_create(&msgid);
		len = sizeof(r);
		if (r == 1)
			len += sizeof(msgid);
		buf = imsg_create(&ibuf, PROC_TABLE_OK, 0, 0, len);
		imsg_add(buf, &r, sizeof(r));
		if (r == 1)
			imsg_add(buf, &msgid, sizeof(msgid));
		imsg_close(&ibuf, buf);
		break;

	case PROC_QUEUE_MESSAGE_DELETE:
	case PROC_QUEUE_MESSAGE_COMMIT:
		if (len != sizeof(msgid)) {
			log_warnx("warn: queue-api: bad message length");
			goto fail;
		}

		memmove(&msgid, data, len);

		if (imsg.hdr.type == PROC_QUEUE_MESSAGE_DELETE)
			r = handler_message_delete(msgid);
		else
			r = handler_message_commit(msgid);

		imsg_compose(&ibuf, PROC_QUEUE_OK, 0, 0, -1, &r, sizeof(r));
		break;

	case PROC_QUEUE_MESSAGE_FD_R:
	case PROC_QUEUE_MESSAGE_FD_RW:
		if (len != sizeof(msgid)) {
			log_warnx("warn: queue-api: bad message length");
			goto fail;
		}

		memmove(&msgid, data, len);

		if (imsg.hdr.type == PROC_QUEUE_MESSAGE_FD_R)
			fd = handler_message_fd_r(msgid);
		else
			fd = handler_message_fd_w(msgid);

		imsg_compose(&ibuf, PROC_QUEUE_OK, 0, 0, fd, NULL, 0);
		break;

	case PROC_QUEUE_MESSAGE_CORRUPT:
		if (len != sizeof(msgid)) {
			log_warnx("warn: queue-api: bad message length");
			goto fail;
		}

		memmove(&msgid, data, len);

		r = handler_message_corrupt(msgid);

		imsg_compose(&ibuf, PROC_QUEUE_OK, 0, 0, -1, &r, sizeof(r));
		break;

	case PROC_QUEUE_ENVELOPE_CREATE:
		if (len <= sizeof(msgid)) {
			log_warnx("warn: queue-api: bad message length");
			goto fail;
		}

		memmove(&msgid, data, len);
		data += sizeof(msgid);
		len -= sizeof(msgid);

		r = handler_envelope_create(msgid, data, len, &evpid);

		len = sizeof(r);
		if (r == 1)
			len += sizeof(evpid);

		buf = imsg_create(&ibuf, PROC_QUEUE_OK, 0, 0, len);
		imsg_add(buf, &r, sizeof(r));
		if (r == 1)
			imsg_add(buf, &evpid, sizeof(evpid));
		imsg_close(&ibuf, buf);
		break;

	case PROC_QUEUE_ENVELOPE_DELETE:
		if (len != sizeof(evpid)) {
			log_warnx("warn: queue-api: bad message length");
			goto fail;
		}

		memmove(&evpid, data, len);

		r = handler_envelope_delete(evpid);

		imsg_compose(&ibuf, PROC_QUEUE_OK, 0, 0, -1, &r, sizeof(r));
		break;

	case PROC_QUEUE_ENVELOPE_LOAD:
		if (len != sizeof(evpid)) {
			log_warnx("warn: queue-api: bad message length");
			goto fail;
		}

		memmove(&evpid, data, len);

		r = handler_envelope_load(evpid, buffer, sizeof(buffer));

		imsg_compose(&ibuf, PROC_QUEUE_OK, 0, 0, -1, buffer, r);

		break;


	case PROC_QUEUE_ENVELOPE_UPDATE:
		if (len <= sizeof(evpid)) {
			log_warnx("warn: queue-api: bad message length");
			goto fail;
		}

		memmove(&evpid, data, len);
		data += sizeof(evpid);
		len -= sizeof(evpid);

		r = handler_envelope_update(evpid, data, len);

		imsg_compose(&ibuf, PROC_QUEUE_OK, 0, 0, -1, &r, sizeof(r));
		break;

	case PROC_QUEUE_ENVELOPE_WALK:
		if (len != 0)  {
			log_warnx("warn: queue-api: bad message length");
			goto fail;
		}

		r = handler_envelope_walk(&evpid);

		len = sizeof(r);
		if (r == 1)
			len += sizeof(evpid);
		buf = imsg_create(&ibuf, PROC_QUEUE_OK, 0, 0, len);
		imsg_add(buf, &r, sizeof(r));
		if (r == 1)
			imsg_add(buf, &evpid, sizeof(evpid));
		imsg_close(&ibuf, buf);
		return (r);

	default:
		log_warnx("warn: queue-api: bad message %i", imsg.hdr.type);
		goto fail;
	}

	return (0);
    fail:
	imsg_compose(&ibuf, PROC_QUEUE_FAIL, 0, 0, -1, NULL, 0);
	return (0);
}

void
queue_api_on_message_create(int(*cb)(uint32_t *))
{
	handler_message_create = cb;
}

void
queue_api_on_message_commit(int(*cb)(uint32_t))
{
	handler_message_commit = cb;
}

void
queue_api_on_message_delete(int(*cb)(uint32_t))
{
	handler_message_delete = cb;
}

void
queue_api_on_message_fd_r(int(*cb)(uint32_t))
{
	handler_message_fd_r = cb;
}

void
queue_api_on_message_fd_w(int(*cb)(uint32_t))
{
	handler_message_fd_w = cb;
}

void
queue_api_on_message_corrupt(int(*cb)(uint32_t))
{
	handler_message_corrupt = cb;
}

void
queue_api_on_envelope_create(int(*cb)(uint32_t, const char *, size_t, uint64_t *))
{
	handler_envelope_create = cb;
}

void
queue_api_on_envelope_delete(int(*cb)(uint64_t))
{
	handler_envelope_delete = cb;
}

void
queue_api_on_envelope_update(int(*cb)(uint64_t, const char *, size_t))
{
	handler_envelope_update = cb;
}

void
queue_api_on_envelope_load(int(*cb)(uint64_t, char *, size_t))
{
	handler_envelope_load = cb;
}

void
queue_api_on_envelope_walk(int(*cb)(uint64_t *))
{
	handler_envelope_walk = cb;
}

int
queue_api_dispatch(void)
{
	ssize_t	n;

	imsg_init(&ibuf, 0);

	while (1) {
		n = imsg_get(&ibuf, &imsg);
		if (n == -1) {
			log_warn("warn: queue-api: imsg_get");
			break;
		}

		if (n) {
			dispatch();
			imsg_flush(&ibuf);
			continue;
		}

		n = imsg_read(&ibuf);
		if (n == -1) {
			log_warn("warn: queue-api: imsg_read");
			break;
		}
		if (n == 0) {
			log_warn("warn: queue-api: pipe closed");
			break;
		}
	}

	return (1);
}
