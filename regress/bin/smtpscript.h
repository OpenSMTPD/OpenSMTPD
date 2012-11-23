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

struct op;

#define		PROC_TESTCASE	0x0001
#define		PROC_SKIP	0x0002
#define		PROC_EXPECTFAIL	0x0004
#define		PROC_NOCONNECT	0x0008


struct variable {
	TAILQ_ENTRY(variable)	 entry;
	char			*name;
};

struct procedure {
	int			 flags;

	TAILQ_ENTRY(procedure)	 entry;
	char			*name;

	TAILQ_HEAD(, variable)	 vars;
	int			 varcount;

	struct op		*root;

	int			 skip;
	int			 expect_fail;
};

#define RESP_SMTP_OK		0x0001
#define RESP_SMTP_TEMPFAIL	0x0002
#define RESP_SMTP_PERMFAIL	0x0004
#define RESP_SMTP_ANY		0x0007

#define RESP_SMTP_MULTILINE	0x0100

struct script {
	TAILQ_HEAD(, procedure)	 procs;
};

int proc_addvar(struct procedure *, char *name);
int proc_getvaridx(struct procedure *, char *name);

struct op *op_block(struct op *);
struct op *op_repeat(struct op *, int, struct op *);
struct op *op_random(struct op *, struct op *);
struct op *op_noop(struct op *);
struct op *op_fail(struct op *, char *);
struct op *op_call(struct op *, struct procedure *);
struct op *op_connect(struct op *, const char *, int);
struct op *op_disconnect(struct op *);
struct op *op_sleep(struct op *, unsigned int);
struct op *op_write(struct op *, const void *, size_t);
struct op *op_printf(struct op *, const char *, ...);

struct op *op_expect_disconnect(struct op *);
struct op *op_expect_smtp_response(struct op *, int);

struct procedure *procedure_create(struct script *, char *);
struct procedure *procedure_get_by_name(struct script *, const char *);

struct script * parse_script(const char *);
