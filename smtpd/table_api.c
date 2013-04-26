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

#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

static int(*handler_update)(void) = NULL;
static int(*handler_check)(int, const char *) = NULL;
static int(*handler_lookup)(int, const char *, char *, size_t) = NULL;
static int(*handler_fetch)(int, char *, size_t) = NULL;

static struct imsgbuf	ibuf;
static struct imsg	imsg;

static int
res_fail(const char *reason)
{
	if (reason)
		log_warnx("warn: table-api: %s", reason);
	imsg_compose(&ibuf, PROC_TABLE_FAIL, 0, 0, -1, NULL, 0);
	return (0);
}

static int
res_ok(void *data, size_t len)
{
	imsg_compose(&ibuf, PROC_TABLE_OK, 0, 0, -1, data, len);
	return (0);
}

static int
dispatch(void)
{
	uint32_t	 version;
	size_t		 len;
	char		 res[4096], *data, *key;
	int		 type, r;
	struct ibuf	*buf;

	data = imsg.data;
	len = imsg.hdr.len - IMSG_HEADER_SIZE;

	switch (imsg.hdr.type) {
	case PROC_TABLE_OPEN:
		if (len != sizeof(version))
			return res_fail("bad message length");
		memmove(&version, data, len);
		if (version != PROC_TABLE_API_VERSION)
			return res_fail("bad API version");
		return res_ok(NULL, 0);

	case PROC_TABLE_UPDATE:
		if (handler_update)
			r = handler_update();
		else
			r = 1;
		return res_ok(&r, sizeof(r));

	case PROC_TABLE_CLOSE:
		return (-1);

	case PROC_TABLE_CHECK:
		if (len <= sizeof (type))
			return res_fail("bad message length");
		memmove(&type, data, sizeof(type));
		key = data + sizeof(type);
		len -= sizeof(type);
		if (key[len] != '\0')
			return res_fail("bad message length");

		if (handler_check)
			r = handler_check(type, key);
		else
			r = -1;
		return res_ok(&r, sizeof(r));

	case PROC_TABLE_LOOKUP:
		if (len <= sizeof (type))
			return res_fail("bad message length");
		memmove(&type, data, sizeof(type));
		key = data + sizeof(type);
		len -= sizeof(type);
		if (key[len] != '\0')
			return res_fail("bad message length");

		if (handler_lookup)
			r = handler_lookup(type, key, res, sizeof(res));
		else
			r = -1;

		len = sizeof(r);
		if (r == 1)
			len += strlen(res) + 1;
		buf = imsg_create(&ibuf, PROC_TABLE_OK, 0, 0, len);
		imsg_add(buf, &r, sizeof(r));
		if (r == 1)
			imsg_add(buf, res, strlen(res) + 1);
		imsg_close(&ibuf, buf);
		return (0);

	case PROC_TABLE_FETCH:
		if (len != sizeof(type))
			return res_fail("bad message length");
		memmove(&type, data, sizeof(type));

		if (handler_fetch)
			r = handler_fetch(type, res, sizeof(res));
		else
			r = -1;
		len = sizeof(r);
		if (r == 1)
			len += strlen(res) + 1;
		buf = imsg_create(&ibuf, PROC_TABLE_OK, 0, 0, len);
		imsg_add(buf, &r, sizeof(r));
		if (r == 1)
			imsg_add(buf, res, strlen(res) + 1);
		imsg_close(&ibuf, buf);
		return (0);

	default:
		log_warnx("warn: table-api: bad message %i", imsg.hdr.type);
		return res_fail(NULL);
	}
}

void
table_api_on_update(int(*cb)(void))
{
	handler_update = cb;
}

void
table_api_on_check(int(*cb)(int, const char *))
{
	handler_check = cb;
}

void
table_api_on_lookup(int(*cb)(int, const char *, char *, size_t))
{
	handler_lookup = cb;
}

void
table_api_on_fetch(int(*cb)(int, char *, size_t))
{
	handler_fetch = cb;
}

int
table_api_dispatch(void)
{
	ssize_t	n;

	imsg_init(&ibuf, 0);

	while (1) {
		n = imsg_get(&ibuf, &imsg);
		if (n == -1) {
			log_warn("warn: table-api: imsg_get");
			break;
		}

		if (n) {
			if (dispatch() == -1)
				break;
			imsg_flush(&ibuf);
			continue;
		}

		n = imsg_read(&ibuf);
		if (n == -1) {
			log_warn("warn: table-api: imsg_read");
			break;
		}
		if (n == 0) {
			log_warnx("warn: table-api: pipe closed");
		}
	}

	return (0);
}
