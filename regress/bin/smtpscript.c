/*	$OpenBSD: iobuf.h,v 1.1 2012/01/29 00:32:51 eric Exp $	*/
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
#include <sys/socket.h>
#include <sys/queue.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vis.h>

#include "iobuf.h"

#include "smtpscript.h"

void   *ssl_connect(int);
void	ssl_close(void *);

/* XXX */
#define SMTP_LINE_MAX	4096

enum {
	OP_BLOCK,
	OP_REPEAT,
	OP_RANDOM,

	OP_NOOP,

	OP_FAIL,
	OP_CALL,
	OP_CONNECT,
	OP_DISCONNECT,
	OP_STARTTLS,
	OP_SLEEP,
	OP_WRITE,

	OP_EXPECT_DISCONNECT,
	OP_EXPECT_SMTP_RESPONSE,
};

struct op {
	struct op	*next;
	int		 type;
	union {
		struct {
			int		 count;
			struct op	*start;
			struct op	*last;
		}	block;
		struct {
			struct op	*op;
			int		 count;
		}	repeat;
		struct {
			struct op	*block;
		}	random;
		struct {
			char		*reason;
		}	fail;
		struct {
			struct procedure *proc;
		}	call;
		struct {
			char		*hostname;
			int		 portno;
		}	connect;
		struct {
			unsigned int	 ms;
		}	sleep;
		struct {
			const void	*buf;
			size_t		 len;
		} write;
		struct {
			int		 flags;
		} expect_smtp;
	} u;
};

#define RES_OK		0
#define RES_SKIP	1
#define RES_FAIL	2
#define RES_ERROR	3

struct ctx {
	int		 sock;
	void		*ssl;
	struct iobuf	 iobuf;
	int		 lvl;

	int		 result;
	char		*reason;
};

static struct op	* _op_connect;

int		verbose;
int		randomdelay; /* between each testcase */
size_t		rundelay; /* between each testcase */

static size_t	test_pass;
static size_t	test_skip;
static size_t	test_fail;
static size_t	test_error;

static struct op *op_add_child(struct op *, const struct op *);
static void run_testcase(struct procedure *);
static void process_op(struct ctx *, struct op *);
static const char * parse_smtp_response(char *, size_t, char **, int *);

struct procedure *
procedure_create(struct script *scr, char *name)
{
	struct procedure	*p;

	if (procedure_get_by_name(scr, name)) {
		warnx("procedure \"%s\" already exists", name);
		return (NULL);
	}

	p = calloc(1, sizeof *p);
	TAILQ_INIT(&p->vars);
	p->name = strdup(name);

	TAILQ_INSERT_TAIL(&scr->procs, p, entry);

	return (p);
}

struct procedure *
procedure_get_by_name(struct script *scr, const char *name)
{
	struct procedure *p;

	TAILQ_FOREACH(p, &scr->procs, entry)
		if (!strcmp(name, p->name))
			return (p);

	return (NULL);
}

int
proc_getvaridx(struct procedure *proc, char *name)
{
	struct variable	*v;
	int		 n;

	n = 0;
	TAILQ_FOREACH(v, &proc->vars, entry) {
		if (!strcmp(name, v->name))
			return (n);
		n++;
	}

	return (-1);
}

int
proc_addvar(struct procedure *proc, char *name)
{
	struct variable	*v;

	printf("adding variable \"%s\"\n", name);

	if (proc_getvaridx(proc, name) != -1)
		return (-1);
	v = calloc(1, sizeof *v);
	v->name = name;
	TAILQ_INSERT_TAIL(&proc->vars, v, entry);

	return (proc->varcount++);
}

struct op *
op_block(struct op *parent)
{
	struct op	o;

	bzero(&o, sizeof o);
	o.type = OP_BLOCK;

	return (op_add_child(parent, &o));
}

struct op *
op_repeat(struct op *parent, int count, struct op *op)
{
	struct op	o;

	bzero(&o, sizeof o);
	o.type = OP_REPEAT;
	o.u.repeat.count = count;
	o.u.repeat.op = op;

	return (op_add_child(parent, &o));
}

struct op *
op_random(struct op *parent, struct op *op)
{
	struct op	o;

	bzero(&o, sizeof o);
	o.type = OP_RANDOM;
	o.u.random.block = op;

	return (op_add_child(parent, &o));
}

struct op *
op_noop(struct op *parent)
{
	struct op	o;

	bzero(&o, sizeof o);
	o.type = OP_NOOP;

	return (op_add_child(parent, &o));
}

struct op *
op_call(struct op *parent, struct procedure *proc)
{
	struct op	o;

	bzero(&o, sizeof o);
	o.type = OP_CALL;
	o.u.call.proc = proc;

	return (op_add_child(parent, &o));
}

struct op *
op_fail(struct op *parent, char *reason)
{
	struct op	o;

	bzero(&o, sizeof o);
	o.type = OP_FAIL;
	o.u.fail.reason = reason;

	return (op_add_child(parent, &o));
}

struct op *
op_connect(struct op *parent, const char *hostname, int portno)
{
	struct op	o;

	bzero(&o, sizeof o);
	o.type = OP_CONNECT;
	o.u.connect.hostname = strdup(hostname);
	o.u.connect.portno = portno;
	return (op_add_child(parent, &o));
}

struct op *
op_disconnect(struct op *parent)
{
	struct op	o;

	bzero(&o, sizeof o);
	o.type	= OP_DISCONNECT;
	return (op_add_child(parent, &o));
}

struct op *
op_starttls(struct op *parent)
{
	struct op	o;

	bzero(&o, sizeof o);
	o.type	= OP_STARTTLS;
	return (op_add_child(parent, &o));
}

struct op *
op_sleep(struct op *parent, unsigned int ms)
{
	struct op	o;

	bzero(&o, sizeof o);
	o.type	= OP_SLEEP;
	o.u.sleep.ms = ms;
	return (op_add_child(parent, &o));
}

struct op *
op_write(struct op *parent, const void *buf, size_t len)
{
	struct op	o;

	bzero(&o, sizeof o);
	o.type	= OP_WRITE;
	o.u.write.buf = buf;
	o.u.write.len = len;
	return (op_add_child(parent, &o));
}

struct op *
op_printf(struct op *parent, const char *fmt, ...)
{
	va_list		 ap;
	char		*buf;
	int		 len;

	va_start(ap, fmt);
	if ((len = vasprintf(&buf, fmt, ap)) == -1)
		err(1, "vasprintf");
	va_end(ap);

	return op_write(parent, buf, len);
}

struct op *
op_expect_disconnect(struct op *parent)
{
	struct op	o;

	bzero(&o, sizeof o);
	o.type	= OP_EXPECT_DISCONNECT;
	return (op_add_child(parent, &o));
}

struct op *
op_expect_smtp_response(struct op *parent, int flags)
{
	struct op	o;

	bzero(&o, sizeof o);
	o.type	= OP_EXPECT_SMTP_RESPONSE;
	o.u.expect_smtp.flags = flags;
	return (op_add_child(parent, &o));
}

static void
usage(void)
{
	extern const char *__progname;
	errx(1, "usage: [-rv] [-d delay] %s script", __progname);
}

int
main(int argc, char **argv)
{
	struct script		*s;
	struct procedure	*p;
	int			 ch;

	while ((ch = getopt(argc, argv, "d:rv")) != -1) {
		switch(ch) {
		case 'v':
			verbose += 1;
			break;
		case 'd':
			rundelay = atoi(optarg) * 1000;
			break;
		case 'r':
			randomdelay = 1;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	s = parse_script(argv[0]);
	if (s == NULL)
		errx(1, "error reading script file");

	_op_connect = op_connect(NULL, "127.0.0.1", 25);

	TAILQ_FOREACH(p, &s->procs, entry)
		if (p->flags & PROC_TESTCASE)
			run_testcase(p);

	printf("===> all run\n");
	printf("passed: %zu/%zu (skipped: %zu, failed: %zu, error: %zu)\n",
		test_pass,
		test_pass + test_skip + test_fail + test_error,
		test_skip,
		test_fail,
		test_error);

	return (0);
}

static struct op *
op_add_child(struct op *parent, const struct op *op)
{
	struct op	*n;

	n = malloc(sizeof *n);
	if (n == NULL)
		err(1, "malloc");

	memmove(n, op, sizeof *n);
	n->next = NULL;

	/* printf("op:%p type:%i parent: %p\n", n, n->type, parent); */

	if (parent) {
		if (parent->u.block.start == NULL)
			parent->u.block.start = n;
		if (parent->u.block.last)
			parent->u.block.last->next = n;
		parent->u.block.last = n;
		parent->u.block.count += 1;
	}

	return (n);
}

static void
run_testcase(struct procedure *proc)
{
	char		 buf[256];
	struct ctx	 c;
	uint32_t	 rdelay;

	bzero(&c, sizeof c);
	c.sock = -1;
	c.lvl = 1;

	if (rundelay) {
		if (randomdelay)
			rdelay = arc4random_uniform(rundelay);
		else
			rdelay = rundelay;
		usleep(rdelay);
	}
	snprintf(buf, sizeof buf,
	    "===> running test-case \"%s\" ", proc->name);
	printf("%s", buf);
	fflush(stdout);

	if (proc->flags & PROC_SKIP) {
		if (verbose > 1)
			printf(": skip\n\n");
		else
			printf("skip\n");
		test_skip += 1;
		return;
	}

	if (verbose > 1)
		printf("\n");

	if (!(proc->flags & PROC_NOCONNECT))
		process_op(&c, _op_connect);
	process_op(&c, proc->root);

	if (c.sock != -1)
		close(c.sock);
	if (c.ssl)
		ssl_close(c.ssl);
	iobuf_clear(&c.iobuf);

	if (verbose > 1) {
		printf("===> done with test-case \"%s\": ", proc->name);
	}

	switch (c.result) {
	case RES_OK:
		if (proc->flags & PROC_EXPECTFAIL) {
			printf("ok (failed)\n");
			fprintf(stderr, "*** FAIL: should have failed\n");
			test_fail += 1;
		} else {
			printf("ok\n");
			test_pass += 1;
		}
		break;

	case RES_SKIP:
		printf("skip\n");
		test_skip += 1;
		break;

	case RES_FAIL:
		if (proc->flags & PROC_EXPECTFAIL) {
			printf("fail (expected)\n");
			test_pass += 1;
		} else {
			printf("fail\n");
			fprintf(stderr, "*** FAIL: %s\n", c.reason);
			test_fail += 1;
		}
		break;

	case RES_ERROR:
		printf("error\n");
		fprintf(stderr, " *** ERROR: %s\n", c.reason);
		test_error += 1;
		break;
	}

	if (verbose > 1) {
		printf("\n");
	}

}

static size_t
strvisx2(char *dst, const char *src, size_t srclen, int flag)
{
	size_t n, r, i;

	n = strvisx(dst, src, srclen, flag);
	if (n == 0)
		return (0);

	r = n;
	for (i = n - 1; i; i--) {
		if (dst[i] == '\r') {
			memmove(dst + i + 2, dst + i + 1, n + 1 - i);
			dst[i+1] = 'r';
			dst[i] = '\\';
			r++;
		} else if (dst[i] == '"') {
			memmove(dst + i + 2, dst + i + 1, n + 1 - i);
			dst[i+1] = '"';
			dst[i] = '\\';
			r++;
		}
	}

	return (r);
}

static const char *
show_data(const char *src, size_t len, size_t max)
{
	static char	buf[8192 + 3];
	char		tmp[256];
	size_t		l, n;

	l = len;
	if (len > 2048)
		l = 2048;

	buf[0] = '"';
	n = strvisx2(&buf[1], src, l, VIS_SAFE | VIS_NL | VIS_TAB | VIS_CSTYLE);
	if (n >= max) {
		snprintf(tmp, sizeof tmp, "...\" [%zu]", l);
		buf[max - strlen(tmp)] = '\0';
		strlcat(buf, tmp, sizeof(buf));
	} else {
		strlcat(buf, "\"", sizeof(buf));
	}

	return (buf);
}

static void
print_op(struct op *op, int lvl)
{


	if (op->type == OP_BLOCK)
		return;

	while (lvl--)
		printf("  ");

	switch(op->type) {

	case OP_REPEAT:
		printf("=> repeat: %i\n", op->u.repeat.count);
		break;

	case OP_RANDOM:
		printf("=> random: %i\n", op->u.random.block->u.block.count);
		break;

	case OP_NOOP:
		printf("=> noop\n");
		break;

	case OP_FAIL:
		printf("=> fail: %s\n", op->u.fail.reason);
		break;

	case OP_CALL:
		printf("=> call: %s\n", op->u.call.proc->name);
		break;
	
	case OP_CONNECT:
		printf("=> connect %s:%i\n",
		    op->u.connect.hostname,
		    op->u.connect.portno);
		break;

	case OP_DISCONNECT:
		printf("=> disconnect\n");
		break;

	case OP_STARTTLS:
		printf("=> starttls\n");
		break;

	case OP_SLEEP:
		printf("=> sleep %ims\n", op->u.sleep.ms);
		break;

	case OP_WRITE:
		printf("=> write %s\n",
		    show_data(op->u.write.buf, op->u.write.len, 70));
		break;

	case OP_EXPECT_DISCONNECT:
		printf("<= disconnect\n");
		break;

	case OP_EXPECT_SMTP_RESPONSE:
		printf("<= smtp-response 0x%04x\n", op->u.expect_smtp.flags);
		break;

	default:
		printf("<> ??? %i;\n", op->type);
		break;
	}
}


static void
set_failure(struct ctx *ctx, int res, const char *fmt, ...)
{
	va_list		 ap;
	int		 len;

	ctx->result = res;
	va_start(ap, fmt);
	if ((len = vasprintf(&ctx->reason, fmt, ap)) == -1)
		err(1, "vasprintf");
	va_end(ap);
}

static void
process_op(struct ctx *ctx, struct op *op)
{
	struct addrinfo	 hints, *a, *ai;
	struct op	*o;
	struct iobuf	*iobuf;
	int		 i, r, s, save_errno, cont;
	const char	*cause;
	char		 buf[16], *servname, *line;
	ssize_t		 n;
	size_t		 len;
	const char	*e;

	if (verbose > 1)
		print_op(op, ctx->lvl);

	iobuf = &ctx->iobuf;

	switch(op->type) {

	case OP_BLOCK:
		ctx->lvl += 1;
		for (o = op->u.block.start; o; o = o->next) {
			process_op(ctx, o);
			if (ctx->result)
				break;
		}
		ctx->lvl -= 1;
		break;

	case OP_REPEAT:
		ctx->lvl += 1;
		for (i = 0; i < op->u.repeat.count; i++) {
			process_op(ctx, op->u.repeat.op);
			if (ctx->result)
				break;
		}
		ctx->lvl -= 1;
		break;

	case OP_RANDOM:

		if (op->u.random.block->u.block.count == 0)
			return;

		ctx->lvl += 1;

		i = arc4random_uniform(op->u.random.block->u.block.count);
		for (o = op->u.random.block->u.block.start; i; i--, o = o->next)
			;
		process_op(ctx, o);
		if (ctx->result)
			break;
		ctx->lvl -= 1;
		break;

	case OP_NOOP:
		break;

	case OP_FAIL:
		set_failure(ctx, RES_FAIL, op->u.fail.reason);
		break;

	case OP_CALL:
		process_op(ctx, op->u.call.proc->root);
		break;

	case OP_CONNECT:
		if (ctx->sock != -1)
			close(ctx->sock);
		ctx->sock = -1;
		iobuf_clear(iobuf);

		servname = NULL;
		if (op->u.connect.portno) {
			snprintf(buf, sizeof buf, "%i", op->u.connect.portno);
			servname = buf;
		}
		bzero(&hints, sizeof hints);
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		r = getaddrinfo(op->u.connect.hostname, servname, &hints, &ai);
		if (r) {
			set_failure(ctx, RES_ERROR,
			    "failed to connect to %s:%s: %s",
			    op->u.connect.hostname, servname, gai_strerror(r));
			return;
		}

		s = -1;
		for(a = ai; a; a = a->ai_next) {
			s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
			if (s == -1) {
				cause = "socket";
				continue;
			}
			if (connect(s, a->ai_addr, a->ai_addrlen) == -1) {
				cause = "connect";
				save_errno = errno;
				close(s);
				errno = save_errno;
				s = -1;
				continue;
			}
			break;  /* okay we got one */
		}
		freeaddrinfo(ai);
		if (s == -1) {
			set_failure(ctx, RES_ERROR,
			    "failed to connect to %s:%s: %s",
			    op->u.connect.hostname, servname, cause);
		} else {
			ctx->sock = s;
			iobuf_init(iobuf, 0, 0);
		}
		break;

	case OP_DISCONNECT:
		if (ctx->sock != -1)
			close(ctx->sock);
		ctx->sock = -1;
		iobuf_clear(iobuf);
		break;

	case OP_STARTTLS:
		if (ctx->ssl)
			set_failure(ctx, RES_ERROR, "SSL context already here");
		else if ((ctx->ssl = ssl_connect(ctx->sock)) == NULL)
			set_failure(ctx, RES_ERROR, "SSL connection failed");
		break;

	case OP_SLEEP:
		usleep(op->u.sleep.ms * 1000);
		break;

	case OP_WRITE:
		iobuf_queue(iobuf, op->u.write.buf, op->u.write.len);
		if (ctx->ssl)
			r = iobuf_flush_ssl(iobuf, ctx->ssl);
		else
			r = iobuf_flush(iobuf, ctx->sock);
		switch (r) {
		case 0:
			break;
		case IOBUF_CLOSED:
			set_failure(ctx, RES_FAIL, "connection closed");
			break;
		case IOBUF_WANT_WRITE:
			set_failure(ctx, RES_ERROR, "iobuf_write(): WANT_WRITE");
			break;
		case IOBUF_ERROR:
			set_failure(ctx, RES_ERROR, "IO error");
			break;
		case IOBUF_SSLERROR:
			set_failure(ctx, RES_ERROR, "SSL error");
			break;
		default:
			set_failure(ctx, RES_ERROR, "iobuf_write(): bad value");
			break;
		}
		break;

	case OP_EXPECT_DISCONNECT:
		if (iobuf_len(iobuf)) {
			set_failure(ctx, RES_ERROR, "%zu bytes of input left",
			    iobuf_len(iobuf));
			break;
		}
		if (ctx->ssl)
			n = iobuf_read_ssl(iobuf, ctx->ssl);
		else
			n = iobuf_read(iobuf, ctx->sock);
		switch (n) {
		case IOBUF_CLOSED:
			close(ctx->sock);
			ctx->sock = -1;
			if (ctx->ssl)
				ssl_close(ctx->ssl);
			break;
		case IOBUF_WANT_READ:
			set_failure(ctx, RES_ERROR, "iobuf_read(): WANT_READ");
			break;
		case IOBUF_ERROR:
			set_failure(ctx, RES_ERROR, "IO error");
			break;
		case IOBUF_SSLERROR:
			set_failure(ctx, RES_ERROR, "SSL error");
			break;
		default:
			set_failure(ctx, RES_FAIL, "data read: %s",
			    show_data(iobuf_data(iobuf), iobuf_len(iobuf), 70));
			break;
		}
		break;

	case OP_EXPECT_SMTP_RESPONSE:
		line = NULL;
		while (1) {
			line = iobuf_getline(iobuf, &len);
			if (line) {
				e = parse_smtp_response(line, len, NULL, &cont);
				if (e) {
					set_failure(ctx, RES_FAIL, e);
					return;
				}
				if (!cont) {
					iobuf_normalize(iobuf);
					break;
				}
				if (!(op->u.expect_smtp.flags
				    & RESP_SMTP_MULTILINE)) {
					set_failure(ctx, RES_FAIL,
					   "single line response expected");
					return;
				}
				continue;
			}

			if (iobuf_len(iobuf) >= SMTP_LINE_MAX) {
				set_failure(ctx, RES_FAIL, "line too long");
				return;
			}

			iobuf_normalize(iobuf);

		    again:
			if (ctx->ssl)
				n = iobuf_read_ssl(iobuf, ctx->ssl);
			else
				n = iobuf_read(iobuf, ctx->sock);
			switch (n) {
			case IOBUF_CLOSED:
				set_failure(ctx, RES_FAIL, "connection closed");
				return;
			case IOBUF_WANT_READ:
				goto again;
			case IOBUF_ERROR:
				set_failure(ctx, RES_ERROR, "io error");
				return;
			case IOBUF_SSLERROR:
				set_failure(ctx, RES_ERROR, "SSL error");
				return;
			default:
				break;
			}
		}

		/* got our response */

		if (verbose > 1) {
			len = ctx->lvl;
			while (len--)
				printf("  ");
			printf("   >>> %s\n", show_data(line, strlen(line), 70));
		}

		switch (line[0]) {
		case '2':
		case '3':
			if (!(op->u.expect_smtp.flags & RESP_SMTP_OK))
				set_failure(ctx, RES_FAIL,
				    "unexpected response code0: %s", line);
			break;
		case '4':
			if (!(op->u.expect_smtp.flags & RESP_SMTP_TEMPFAIL))
				set_failure(ctx, RES_FAIL,
				    "unexpected response code1: %s", line);
			break;
		case '5':
			if (!(op->u.expect_smtp.flags & RESP_SMTP_PERMFAIL))
				set_failure(ctx, RES_FAIL,
				    "unexpected response code2: %s", line);
			break;
		default:
			set_failure(ctx, RES_FAIL,
				    "unexpected response code???: %s", line);
			break;
		}
		break;

	default:
		ctx->result = RES_ERROR;
		ctx->reason = "invalid operator";
		break;
	}
}

static const char *
parse_smtp_response(char *line, size_t len, char **msg, int *cont)
{
	size_t	 i;

	if (len >= SMTP_LINE_MAX)
		return "line too long";

	if (len > 3) {
		if (msg)
			*msg = line + 4;
		if (cont)
			*cont = (line[3] == '-');
	} else if (len == 3) {
		if (msg)
			*msg = line + 3;
		if (cont)
			*cont = 0;
	} else
		return "line too short";

	/* validate reply code */
	if (line[0] < '2' || line[0] > '5' || !isdigit(line[1]) ||
	    !isdigit(line[2]))
		return "reply code out of range";

	/* validate reply message */
	for (i = 0; i < len; i++)
		if (!isprint(line[i]))
			return "non-printable character in reply";

	return NULL;
}
