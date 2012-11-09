/*	$OpenBSD: parse.y,v 1.109 2012/10/14 11:58:23 gilles Exp $	*/

/*
 * Copyright (c) 2012 Eric Faurot <eric@openbsd.org>
 * Copyright (c) 2008 Gilles Chehade <gilles@openbsd.org>
 * Copyright (c) 2008 Pierre-Yves Ritschard <pyr@openbsd.org>
 * Copyright (c) 2002, 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
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

%{
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <inttypes.h>
#include <netdb.h>
#include <paths.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include "smtpscript.h"

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	int			 lineno;
	int			 errors;
} *file, *topfile;
struct file	*pushfile(const char *, int);
int		 popfile(void);
int		 check_file_secrecy(int, const char *);
int		 yyparse(void);
int		 yylex(void);
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 lgetc(int);
int		 lungetc(int);
int		 findeol(void);
int		 yyerror(const char *, ...)
    __attribute__ ((format (printf, 1, 2)));

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};
int		 symset(const char *, const char *, int);
char		*symget(const char *);

void	   push_op(struct op *);
struct op *peek_op(void);
struct op *pop_op(void);

#define MAXDEPTH 50

static struct op *	opstack[MAXDEPTH];
static int		opstackidx;

static int errors = 0;

static struct script	*currscript;
static struct procedure	*currproc;

int		 delaytonum(char *);

typedef struct {
	union {
		int64_t		 number;
		char		*string;
		struct op	*op;
	} v;
	int lineno;
} YYSTYPE;

%}

%token  INCLUDE PORT REPEAT RANDOM NOOP
%token	PROC TESTCASE NAME NO_AUTOCONNECT EXPECT FAIL SKIP
%token	CALL CONNECT DISCONNECT SLEEP WRITE WRITELN
%token	SMTP OK TEMPFAIL PERMFAIL HELO
%token	ERROR ARROW
%token	<v.string>	STRING
%token  <v.number>	NUMBER
%type	<v.number>	quantifier port duration size
%type	<v.op>		statement block
%%

grammar		: /* empty */
		| grammar '\n'
		| grammar include '\n'
		| grammar varset '\n'
		| grammar proc '\n'
		| grammar testcase '\n'
		| grammar error '\n'		{ file->errors++; }
		;

include		: INCLUDE STRING		{
			struct file	*nfile;

			if ((nfile = pushfile($2, 0)) == NULL) {
				yyerror("failed to include file %s", $2);
				free($2);
				YYERROR;
			}
			free($2);

			file = nfile;
			lungetc('\n');
		}
		;

varset		: STRING '=' STRING		{
			if (symset($1, $3, 0) == -1)
				errx(1, "cannot store variable");
			free($1);
			free($3);
		}
		;

optnl		: '\n' optnl
		|
		;

nl		: '\n' optnl
		;

quantifier      : /* empty */                   { $$ = 1; }
		| 's'				{ $$ = 1000; }
		| 'm'                           { $$ = 60 * 1000; }
		| 'h'                           { $$ = 3600 * 1000; }
		;

duration	: NUMBER quantifier		{
			if ($1 < 0) {
				yyerror("invalid duration: %" PRId64, $1);
				YYERROR;
			}
			$$ = $1 * $2;
		}
		;

size		: NUMBER		{
			if ($1 < 0) {
				yyerror("invalid size: %" PRId64, $1);
				YYERROR;
			}
			$$ = $1;
		}
		| STRING			{
			long long result;

			if (scan_scaled($1, &result) == -1 || result < 0) {
				yyerror("invalid size: %s", $1);
				YYERROR;
			}
			free($1);

			$$ = result;
		}
		;

port		: PORT STRING			{
			struct servent	*servent;

			servent = getservbyname($2, "tcp");
			if (servent == NULL) {
				yyerror("port %s is invalid", $2);
				free($2);
				YYERROR;
			}
			$$ = ntohs(servent->s_port);
			free($2);
		}
		| PORT NUMBER			{
			if ($2 <= 0 || $2 >= (int)USHRT_MAX) {
				yyerror("invalid port: %" PRId64, $2);
				YYERROR;
			}
			$$ = $2;
		}
		| /* empty */ {
			$$ = 25;
		}
		;

statement	: block
		| REPEAT NUMBER { push_op(NULL); } statement {
			pop_op();
			$$ = op_repeat(peek_op(), $2, $4);
		}
		| RANDOM { push_op(NULL); } block {
			pop_op();
			$$ = op_random(peek_op(), $3);
		}
		| CALL STRING {
			struct procedure *p;
			p = procedure_get_by_name(currscript, $2);
			if (p == NULL) {
				yyerror("call to undefined proc \"%s\"", $2);
				file->errors++;
			} else if (p == currproc) {
				yyerror("recursive call to proc \"%s\"", $2);
				file->errors++;
			} else {
				$$ = op_call(peek_op(), p);
			}
			free($2);
		}
		| NOOP {
			$$ = op_noop(peek_op());
		}
		| SLEEP duration {
			$$ = op_sleep(peek_op(), $2);
		}
		| FAIL STRING {
			$$ = op_fail(peek_op(), $2);
		}
		| CONNECT STRING port {
			$$ = op_connect(peek_op(), $2, $3);
		}
		| DISCONNECT {
			$$ = op_disconnect(peek_op());
		}
		| WRITE STRING {
			$$ = op_write(peek_op(), $2, strlen($2));
		}
		| WRITELN STRING {
			$$ = op_printf(peek_op(), "%s\r\n", $2);
			free($2);
		}
		| EXPECT DISCONNECT {
			$$ = op_expect_disconnect(peek_op());
		}
		| EXPECT SMTP {
			$$ = op_expect_smtp_response(peek_op(),
			    RESP_SMTP_ANY | RESP_SMTP_MULTILINE);
		}
		| EXPECT SMTP OK {
			$$ = op_expect_smtp_response(peek_op(),
			    RESP_SMTP_OK);
		}
		| EXPECT SMTP HELO {
			$$ = op_expect_smtp_response(peek_op(),
			    RESP_SMTP_OK | RESP_SMTP_MULTILINE);
		}
		| EXPECT SMTP TEMPFAIL {
			$$ = op_expect_smtp_response(peek_op(),
			    RESP_SMTP_TEMPFAIL);
		}
		| EXPECT SMTP PERMFAIL {
			$$ = op_expect_smtp_response(peek_op(),
			    RESP_SMTP_PERMFAIL);
		}
		;

statement_list	: statement nl statement_list
		| statement
		| /* EMPTY */
		;

block		: '{' {
			push_op(op_block(peek_op()));
		} optnl statement_list '}' {
			$$ = pop_op();
		}
		;

procparam	: '%' STRING {
			if (proc_addvar(currproc, $2) == -1) {
				yyerror("cannot add parameter %s", $2);
				file->errors++;
			}
		}
		;

procparams	: procparam procparams
		| /* EMPTY */
		;

proc		: PROC STRING {
			printf("proc %s\n", $2);
			currproc = procedure_create(currscript, $2);
			if (currproc == NULL)
				file->errors++;
		} procparams block {
			if (currproc)
				currproc->root = $5;
		}
		;

testopt_name	: NAME STRING {
			if (procedure_get_by_name(currscript, $2)) {
				file->errors++;
			} else {
				free(currproc->name);
				currproc->name = ($2);
			}
		}
		| /* EMPTY */
		;

testopt_cnx	: NO_AUTOCONNECT {
			currproc->flags |= PROC_NOCONNECT;
		}
		| /* EMPTY */
		;
testopt_fail	: EXPECT FAIL {
			currproc->flags |= PROC_EXPECTFAIL;
		}
		| /* EMPTY */
		;

testopt_skip	: SKIP {
			currproc->flags |= PROC_SKIP;
		}
		| /* EMPTY */
		;

testcaseopts	: testopt_name testopt_cnx testopt_fail testopt_skip;

testcase	: TESTCASE {
			char buf[1024];
			snprintf(buf, sizeof buf, "<%s:%i>",
			    file->name, file->lineno);
			currproc = procedure_create(currscript, strdup(buf));
			if (currproc) {
				currproc->flags |= PROC_TESTCASE;
			} else {
				file->errors++;
			}
		} testcaseopts block {
			currproc->root = $4;
		}
		;
%%

struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;

	file->errors++;
	va_start(ap, fmt);
	fprintf(stderr, "%s:%d: ", file->name, yylval.lineno);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	return (0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

int
lookup(char *s)
{
	/* this has to be sorted always */
	static const struct keywords keywords[] = {
		{ "call",		CALL },
		{ "connect",		CONNECT },
		{ "disconnect",		DISCONNECT },
		{ "expect",		EXPECT },
		{ "fail",		FAIL },
		{ "helo",		HELO },
		{ "no-autoconnect",	NO_AUTOCONNECT },
		{ "noop",		NOOP },
		{ "ok",			OK },
		{ "permfail",		PERMFAIL },
		{ "port",		PORT },
		{ "proc",		PROC },
		{ "random",		RANDOM },
		{ "repeat",		REPEAT },
		{ "skip",		SKIP },
		{ "sleep",		SLEEP },
		{ "smtp",		SMTP },
		{ "tempfail",		TEMPFAIL },
		{ "test-case",		TESTCASE },
		{ "write",		WRITE },
		{ "writeln",		WRITELN },
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (STRING);
}

#define MAXPUSHBACK	128

char	*parsebuf;
int	 parseindex;
char	 pushback_buffer[MAXPUSHBACK];
int	 pushback_index = 0;

int
lgetc(int quotec)
{
	int		c, next;

	if (parsebuf) {
		/* Read character from the parsebuffer instead of input. */
		if (parseindex >= 0) {
			c = parsebuf[parseindex++];
			if (c != '\0')
				return (c);
			parsebuf = NULL;
		} else
			parseindex++;
	}

	if (pushback_index)
		return (pushback_buffer[--pushback_index]);

	if (quotec) {
		if ((c = getc(file->stream)) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return (EOF);
			return (quotec);
		}
		return (c);
	}

	while ((c = getc(file->stream)) == '\\') {
		next = getc(file->stream);
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	while (c == EOF) {
		if (file == topfile || popfile() == EOF)
			return (EOF);
		c = getc(file->stream);
	}
	return (c);
}

int
lungetc(int c)
{
	if (c == EOF)
		return (EOF);
	if (parsebuf) {
		parseindex--;
		if (parseindex >= 0)
			return (c);
	}
	if (pushback_index < MAXPUSHBACK-1)
		return (pushback_buffer[pushback_index++] = c);
	else
		return (EOF);
}

int
findeol(void)
{
	int	c;

	parsebuf = NULL;
	pushback_index = 0;

	/* skip to either EOF or the first real EOL */
	while (1) {
		c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}

int
yylex(void)
{
	char	 buf[8096];
	char	*p, *val;
	int	 quotec, next, c;
	int	 token;

top:
	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && parsebuf == NULL) {
		while (1) {
			if ((c = lgetc(0)) == EOF)
				return (0);

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			if (isalnum(c) || c == '_') {
				*p++ = (char)c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro '%s' not defined", buf);
			return (findeol());
		}
		parsebuf = val;
		parseindex = 0;
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return (0);
				if (next == quotec || c == ' ' || c == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = (char)c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			err(1, "yylex: strdup");
		return (STRING);
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum(buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return (findeol());
			}
			return (NUMBER);
		} else {
nodigits:
			while (p > buf + 1)
				lungetc(*--p);
			c = *--p;
			if (c == '-')
				return (c);
		}
	}

	if (c == '=') {
		if ((c = lgetc(0)) != EOF && c == '>')
			return (ARROW);
		lungetc(c);
		c = '=';
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && x != '<' && x != '>' && \
	x != '!' && x != '=' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_') {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				err(1, "yylex: strdup");
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

int
check_file_secrecy(int fd, const char *fname)
{
	struct stat	st;

	if (fstat(fd, &st)) {
		warn("cannot stat %s", fname);
		return (-1);
	}
	if (st.st_uid != 0 && st.st_uid != getuid()) {
		warnx("%s: owner not root or current user", fname);
		return (-1);
	}
	if (st.st_mode & (S_IRWXG | S_IRWXO)) {
		warnx("%s: group/world readable/writeable", fname);
		return (-1);
	}
	return (0);
}

struct file *
pushfile(const char *name, int secret)
{
	struct file	*nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		warn("malloc");
		return (NULL);
	}
	if ((nfile->name = strdup(name)) == NULL) {
		warn("malloc");
		free(nfile);
		return (NULL);
	}
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		warn("%s", nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	} else if (secret &&
	    check_file_secrecy(fileno(nfile->stream), nfile->name)) {
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = 1;
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return (nfile);
}

int
popfile(void)
{
	struct file	*prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file);
	file = prev;
	return (file ? 0 : EOF);
}

struct script *
parse_script(const char *filename)
{
	errors = 0;

	currscript = calloc(1, sizeof *currscript);
	TAILQ_INIT(&currscript->procs);
	currproc = NULL;

	opstackidx = 0;

	if ((file = pushfile(filename, 0)) == NULL)
		return (NULL);

	topfile = file;

	/*
	 * parse configuration
	 */
	setservent(1);
	yyparse();
	errors = file->errors;
	popfile();
	endservent();

	if (errors)
		return (NULL);

	return (currscript);
}

int
symset(const char *nam, const char *val, int persist)
{
	struct sym	*sym;

	for (sym = TAILQ_FIRST(&symhead); sym && strcmp(nam, sym->nam);
	    sym = TAILQ_NEXT(sym, entry))
		;	/* nothing */

	if (sym != NULL) {
		if (sym->persist == 1)
			return (0);
		else {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}
	if ((sym = calloc(1, sizeof(*sym))) == NULL)
		return (-1);

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return (-1);
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
		free(sym->nam);
		free(sym);
		return (-1);
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return (0);
}

int
cmdline_symset(char *s)
{
	char	*sym, *val;
	int	ret;
	size_t	len;

	if ((val = strrchr(s, '=')) == NULL)
		return (-1);

	len = strlen(s) - strlen(val) + 1;
	if ((sym = malloc(len)) == NULL)
		errx(1, "cmdline_symset: malloc");

	(void)strlcpy(sym, s, len);

	ret = symset(sym, val + 1, 1);
	free(sym);

	return (ret);
}

char *
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry)
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	return (NULL);
}

int
delaytonum(char *str)
{
	unsigned int     factor;
	size_t           len;
	const char      *errstr = NULL;
	int              delay;
  	
	/* we need at least 1 digit and 1 unit */
	len = strlen(str);
	if (len < 2)
		goto bad;
	
	switch(str[len - 1]) {
		
	case 's':
		factor = 1;
		break;
		
	case 'm':
		factor = 60;
		break;
		
	case 'h':
		factor = 60 * 60;
		break;
		
	case 'd':
		factor = 24 * 60 * 60;
		break;
		
	default:
		goto bad;
	}
  	
	str[len - 1] = '\0';
	delay = strtonum(str, 1, INT_MAX / factor, &errstr);
	if (errstr)
		goto bad;
	
	return (delay * factor);
  	
bad:
	return (-1);
}


void
push_op(struct op *op)
{
	if (opstackidx == MAXDEPTH) {
		yyerror("too deep");
		return;
	}
	opstack[opstackidx++] = op;
}

struct op *
pop_op(void)
{
	if (opstackidx == 0)
		return (NULL);
	return (opstack[--opstackidx]);
}

struct op *
peek_op(void)
{
	if (opstackidx == 0)
		return (NULL);
	return (opstack[opstackidx - 1]);
}
