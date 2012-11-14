/*	$OpenBSD: queue_fsqueue.c,v 1.53 2012/08/30 18:19:50 eric Exp $	*/

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

#include "includes.h"

#include <sys/types.h>
#include "sys-queue.h"
#include "sys-tree.h"
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

static int queue_ram_init(int);
static int queue_ram_message(enum queue_op, uint32_t *);
static int queue_ram_envelope(enum queue_op , uint64_t *, char *, size_t);
static void *queue_ram_qwalk_new(uint32_t);
static int queue_ram_qwalk(void *, uint64_t *);
static void queue_ram_qwalk_close(void *);

struct queue_backend	queue_backend_ram = {
	  queue_ram_init,
	  queue_ram_message,
	  queue_ram_envelope,
	  queue_ram_qwalk_new,
	  queue_ram_qwalk,
	  queue_ram_qwalk_close
};

struct qr_envelope {
	char		*buf;
	size_t		 len;
};

struct qr_message {
	char		*buf;
	size_t		 len;
	struct tree	 envelopes;
};

static struct tree messages;

static int
queue_ram_init(int server)
{
	tree_init(&messages);

	return (1);
}

static int
queue_ram_message(enum queue_op qop, uint32_t *msgid)
{
	char			 path[MAXPATHLEN];
	uint64_t		 evpid;
	struct qr_envelope	*evp;
	struct qr_message 	*msg;
	int			 fd;
	struct stat		 sb;
	FILE			*f;

        switch (qop) {
        case QOP_CREATE:
		msg = xcalloc(1, sizeof *msg, "queue_ram_message");
		tree_init(&msg->envelopes);
		do {
			*msgid = queue_generate_msgid();
		} while (tree_check(&messages, *msgid));
		queue_message_incoming_path(*msgid, path, sizeof(path));
		if (mkdir(path, 0700) == -1) {
			log_warn("queue_ram_message: mkdir");
			return (0);
		}
		tree_xset(&messages, *msgid, msg);
		return (1);

        case QOP_DELETE:
		msg = tree_pop(&messages, *msgid);
		if (msg == NULL)
			return (0);
		while (tree_poproot(&messages, &evpid, (void**)&evp)) {
			stat_decrement("queue.ram.envelope.size", evp->len);
			free(evp->buf);
			free(evp);
		}
		stat_decrement("queue.ram.message.size", msg->len);
		free(msg->buf);
		return (1);

        case QOP_COMMIT:
		msg = tree_get(&messages, *msgid);
		if (msg == NULL)
			return (0);
		queue_message_incoming_path(*msgid, path, sizeof(path));
		strlcat(path, PATH_MESSAGE, sizeof(path));
		if (stat(path, &sb) == -1) {
			log_warn("queue_ram_message: stat");
			return (0);
		}
		f = fopen(path, "rb");
		if (f == NULL) {
			log_warn("queue_ram: fopen");
			return (0);
		}
		msg->len = sb.st_size;
		msg->buf = xmalloc(msg->len, "queue_ram_message");
		fread(msg->buf, 1, msg->len, f);
		fclose(f);
		unlink(path);
		queue_message_incoming_path(*msgid, path, sizeof(path));
		unlink(path);
		stat_increment("queue.ram.message.size", msg->len);
		return (1);

        case QOP_FD_R:
		msg = tree_get(&messages, *msgid);
		if (msg == NULL)
			return (0);
		fd = mktmpfile();
		if (fd == -1)
			return (-1);
		write(fd, msg->buf, msg->len);
		lseek(fd, 0, SEEK_SET);
                return (fd);

	case QOP_CORRUPT:
		return (queue_ram_message(QOP_DELETE, msgid));

        default:
		fatalx("queue_queue_ram_message: unsupported operation.");
        }

	return (0);
}

static int
queue_ram_envelope(enum queue_op qop, uint64_t *evpid, char *buf, size_t len)
{
	struct qr_envelope	*evp;
	struct qr_message	*msg;
	uint32_t		 msgid;

	msgid = evpid_to_msgid(*evpid);
	msg = tree_get(&messages, msgid);
	if (msg == NULL) {
		log_debug("message not found: %" PRIx32 , msgid);
		return (0);
	}

        switch (qop) {
        case QOP_CREATE:
		do {
			*evpid = queue_generate_evpid(msgid);
		} while (tree_check(&msg->envelopes, *evpid));
		evp = xcalloc(1, sizeof *evp, "queue_ram_envelope: create");
		evp->len = len;
		evp->buf = xmemdup(buf, len, "queue_ram_envelope: create");
		stat_increment("queue.ram.envelope.size", len);
		tree_xset(&msg->envelopes, *evpid, evp);
		return (1);

        case QOP_DELETE:
		evp = tree_pop(&msg->envelopes, *evpid);
		if (evp == NULL)
			return (0);
		stat_decrement("queue.ram.envelope.size", evp->len);
		free(evp->buf);
		free(evp);

		if (tree_empty(&msg->envelopes)) {
			tree_xpop(&messages, msgid);
			stat_decrement("queue.ram.message.size", msg->len);
			free(msg->buf);
			free(msg);
		}
		return (1);

        case QOP_LOAD:
		evp = tree_get(&msg->envelopes, *evpid);
		if (evp == NULL) {
			log_debug("cannot find envelope %016" PRIx64, *evpid);
			return (0);
		}
		if (len < evp->len) {
			log_debug("buffer too short (%zu/%zu)", len, evp->len);
			return (0);
		}
		memmove(buf, evp->buf, evp->len);
		return (evp->len);

        case QOP_UPDATE:
		evp = tree_get(&msg->envelopes, *evpid);
		if (evp == NULL)
			return (0);
		stat_decrement("queue.ram.envelope.size", evp->len);
		stat_increment("queue.ram.envelope.size", len);
		free(evp->buf);
		evp->len = len;
		evp->buf = xmemdup(buf, len, "queue_ram_envelope: update");
		return (1);

        default:
		fatalx("queue_queue_ram_envelope: unsupported operation.");
        }

	return (0);
}

static void *
queue_ram_qwalk_new(uint32_t msgid)
{
	return (NULL);
}

static void
queue_ram_qwalk_close(void *hdl)
{
}

static int
queue_ram_qwalk(void *hdl, uint64_t *evpid)
{
        return (0); 
}
