/*	$OpenBSD$	*/

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
#include <sys/tree.h>
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

struct qr_envelope {
	char		*buf;
	size_t		 len;
};

struct qr_message {
	int		 hasfile;
	char		*buf;
	size_t		 len;
	struct tree	 envelopes;
};

static struct tree messages;

static struct qr_message *
get_message(uint32_t msgid)
{
	struct qr_message	*msg;

        msg = tree_get(&messages, msgid);
        if (msg == NULL)
                log_warn("warn: queue-ram: message not found");

	return (msg);
}

static int
queue_ram_message_create(uint32_t *msgid)
{
	struct qr_message	*msg;

	msg = calloc(1, sizeof(*msg));
	if (msg == NULL) {
		log_warn("warn: queue-ram: calloc");
		return (0);
	}
	tree_init(&msg->envelopes);

	do {
		*msgid = queue_generate_msgid();
	} while (tree_check(&messages, *msgid));

	tree_xset(&messages, *msgid, msg);

	return (1);
}

static int
queue_ram_message_commit(uint32_t msgid)
{
	struct qr_message	*msg;
	struct stat		 sb;
	size_t			 n;
	FILE			*f;
	char			 path[SMTPD_MAXPATHLEN];
	int			 ret;

	if ((msg = tree_get(&messages, msgid)) == NULL) {
		log_warnx("warn: queue-ram: msgid not found");
		return (0);
	}
	queue_message_incoming_path(msgid, path, sizeof(path));
	f = fopen(path, "rb");
	if (f == NULL) {
		log_warn("warn: queue-ram: fopen");
		return (0);
	}
	if (fstat(fileno(f), &sb) == -1) {
		log_warn("warn: queue-ram: fstat");
		fclose(f);
		return (0);
	}

	msg->len = sb.st_size;
	msg->buf = malloc(msg->len);
	if (msg->buf == NULL) {
		log_warn("warn: queue-ram: malloc");
		fclose(f);
		return (0);
	}

	ret = 0;
	n = fread(msg->buf, 1, msg->len, f);
	if (ferror(f))
		log_warn("warn: queue-ram: fread");
	else if ((off_t)n != sb.st_size)
		log_warnx("warn: queue-ram: bad read");
	else {
		ret = 1;
		stat_increment("queue.ram.message.size", msg->len);
	}
	fclose(f);
	if (unlink(path) == -1)
		log_warn("warn: queue-ram: unlink");
	msg->hasfile = 0;

	return (ret);
}

static int
queue_ram_message_delete(uint32_t msgid)
{
	struct qr_message	*msg;
	struct qr_envelope	*evp;
	uint64_t		 evpid;
	char			 path[SMTPD_MAXPATHLEN];

	if ((msg = tree_pop(&messages, msgid)) == NULL) {
		log_warnx("warn: queue-ram: not found");
		return (0);
	}
	while (tree_poproot(&messages, &evpid, (void**)&evp)) {
		stat_decrement("queue.ram.envelope.size", evp->len);
		free(evp->buf);
		free(evp);
	}
	stat_decrement("queue.ram.message.size", msg->len);
	free(msg->buf);
	if (msg->hasfile) {
		queue_message_incoming_path(msgid, path, sizeof(path));
		if (unlink(path) == -1)
			log_warn("warn: queue-ram: unlink");
	}
	free(msg);
	return (0);
}

static int
queue_ram_message_fd_r(uint32_t msgid)
{
	struct qr_message	*msg;
	size_t			 n;
	FILE			*f;
	char			 path[SMTPD_MAXPATHLEN];
	int			 fd, fd2;

	if ((msg = tree_get(&messages, msgid)) == NULL) {
		log_warnx("warn: queue-ram: not found");
		return (-1);
	}

	queue_message_incoming_path(msgid, path, sizeof(path));
	fd = open(path, O_CREAT | O_RDWR | O_EXCL);
	if (fd == -1) {
		log_warn("warn: queue-ram: open");
		return (-1);
	}

	if (unlink(path) == -1)
		log_warn("warn: queue-ram: unlink");

	fd2 = dup(fd);
	if (fd2 == -1) {
		log_warn("warn: queue-ram: dup");
		close(fd);
		return (-1);
	}
	f = fdopen(fd2, "w");
	if (f == NULL) {
		log_warn("warn: queue-ram: fdopen");
		close(fd);
		close(fd2);
		return (-1);
	}
	n = fwrite(msg->buf, 1, msg->len, f);
	if (n != msg->len) {
		log_warn("warn: queue-ram: write");
		close(fd);
		fclose(f);
		return (-1);
	}
	fclose(f);
	lseek(fd, 0, SEEK_SET);
	return (fd);
}

static int
queue_ram_message_fd_w(uint32_t msgid)
{
	struct qr_message	*msg;
	char			 path[SMTPD_MAXPATHLEN];
	int			 fd;

	if ((msg = tree_get(&messages, msgid)) == NULL) {
		log_warnx("warn: queue-ram: not found");
		return (-1);
	}
	queue_message_incoming_path(msgid, path, sizeof(path));
	fd = open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd == -1) {
		log_warn("warn: queue-ram: open");
		return (-1);
	}
	msg->hasfile = 1;
	return (fd);
}

static int
queue_ram_message_corrupt(uint32_t msgid)
{
	return (queue_ram_message_delete(msgid));
}

static int
queue_ram_envelope_create(uint32_t msgid, const char *buf, size_t len,
    uint64_t *evpid)
{
	struct qr_envelope	*evp;
	struct qr_message	*msg;

	if ((msg = get_message(msgid)) == NULL)
		return (0);

	do {
		*evpid = queue_generate_evpid(msgid);
	} while (tree_check(&msg->envelopes, *evpid));
	evp = calloc(1, sizeof *evp);
	if (evp == NULL) {
		log_warn("warn: queue-ram: calloc");
		return (0);
	}
	evp->len = len;
	evp->buf = malloc(len);
	if (evp->buf == NULL) {
		log_warn("warn: queue-ram: malloc");
		free(evp);
		return (0);
	}
	memmove(evp->buf, buf, len);
	tree_xset(&msg->envelopes, *evpid, evp);
	stat_increment("queue.ram.envelope.size", len);
	return (1);
}

static int
queue_ram_envelope_delete(uint64_t evpid)
{
	struct qr_envelope	*evp;
	struct qr_message	*msg;

	if ((msg = get_message(evpid_to_msgid(evpid))) == NULL)
		return (0);

	if ((evp = tree_pop(&msg->envelopes, evpid)) == NULL) {
		log_warnx("warn: queue-ram: not found");
		return (0);
	}
	stat_decrement("queue.ram.envelope.size", evp->len);
	free(evp->buf);
	free(evp);
	if (tree_empty(&msg->envelopes)) {
		tree_xpop(&messages, evpid_to_msgid(evpid));
		stat_decrement("queue.ram.message.size", msg->len);
		free(msg->buf);
		free(msg);
	}
	return (1);
}

static int
queue_ram_envelope_update(uint64_t evpid, const char *buf, size_t len)
{
	struct qr_envelope	*evp;
	struct qr_message	*msg;
	void			*tmp;

	if ((msg = get_message(evpid_to_msgid(evpid))) == NULL)
		return (0);

	if ((evp = tree_get(&msg->envelopes, evpid)) == NULL) {
		log_warn("warn: queue-ram: not found");
		return (0);
	}
	tmp = malloc(len);
	if (tmp == NULL) {
		log_warn("warn: queue-ram: malloc");
		return (0);
	}
	memmove(tmp, buf, len);
	free(evp->buf);
	evp->len = len;
	evp->buf = tmp;
	stat_decrement("queue.ram.envelope.size", evp->len);
	stat_increment("queue.ram.envelope.size", len);
	return (1);
}

static int
queue_ram_envelope_load(uint64_t evpid, char *buf, size_t len)
{
	struct qr_envelope	*evp;
	struct qr_message	*msg;

	if ((msg = get_message(evpid_to_msgid(evpid))) == NULL)
		return (0);

	if ((evp = tree_get(&msg->envelopes, evpid)) == NULL) {
		log_warn("warn: queue-ram: not found");
		return (0);
	}
	if (len < evp->len) {
		log_warnx("warn: queue-ram: buffer too small");
		return (0);
	}
	memmove(buf, evp->buf, evp->len);
	return (evp->len);
}

static int
queue_ram_envelope_walk(uint64_t *evpid)
{
	return (-1);
}

static int queue_ram_init(int);
static int queue_ram_message(enum queue_op, uint32_t *);
static int queue_ram_envelope(enum queue_op , uint64_t *, char *, size_t);

struct queue_backend	queue_backend_ram = {
	queue_ram_init,
	queue_ram_message,
	queue_ram_envelope,
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
	switch (qop) {
	case QOP_CREATE:
		return queue_ram_message_create(msgid);
	case QOP_DELETE:
		return queue_ram_message_delete(*msgid);
	case QOP_COMMIT:
		return queue_ram_message_commit(*msgid);
	case QOP_FD_R:
		return queue_ram_message_fd_r(*msgid);
	case QOP_FD_RW:
		return queue_ram_message_fd_w(*msgid);
	case QOP_CORRUPT:
		return queue_ram_message_corrupt(*msgid);
	default:
		fatalx("queue_ram_message: unsupported operation.");
	}

	return (0);
}

static int
queue_ram_envelope(enum queue_op qop, uint64_t *evpid, char *buf, size_t len)
{
	uint32_t	msgid;

	switch (qop) {
	case QOP_CREATE:
		msgid = evpid_to_msgid(*evpid);
		return queue_ram_envelope_create(msgid, buf, len, evpid);
	case QOP_DELETE:
		return queue_ram_envelope_delete(*evpid);
	case QOP_LOAD:
		return queue_ram_envelope_load(*evpid, buf, len);
	case QOP_UPDATE:
		return queue_ram_envelope_update(*evpid, buf, len);
	case QOP_WALK:
		return queue_ram_envelope_walk(evpid);
	default:
		fatalx("queue_ram_envelope: unsupported operation.");
	}

	return (0);
}
