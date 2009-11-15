#ifndef lint
static const char yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93";
#endif
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define yyclearin (yychar=(-1))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING (yyerrflag!=0)
extern int yyparse(void);
#define YYPREFIX "yy"
#line 25 "parse.y"
#include <sys/types.h>
#include <sys/time.h>
#include "sys-queue.h"
#include "sys-tree.h"
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <ifaddrs.h>
#include <limits.h>
#include <pwd.h>
/* need to define __USE_GNU to get EAI_NODATA defined */
#define __USE_GNU
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd.h"

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

struct smtpd		*conf = NULL;
static int		 errors = 0;

objid_t			 last_map_id = 0;
struct map		*map = NULL;
struct rule		*rule = NULL;
struct mapel_list	*contents = NULL;

struct listener	*host_v4(const char *, in_port_t);
struct listener	*host_v6(const char *, in_port_t);
int		 host_dns(const char *, struct listenerlist *,
		    int, in_port_t, u_int8_t);
int		 host(const char *, struct listenerlist *,
		    int, in_port_t, u_int8_t);
int		 interface(const char *, struct listenerlist *, int, in_port_t,
		    u_int8_t);

typedef struct {
	union {
		int64_t		 number;
		objid_t		 object;
		struct timeval	 tv;
		struct cond	*cond;
		char		*string;
		struct host	*host;
	} v;
	int lineno;
} YYSTYPE;

#line 104 "parse.c"
#define QUEUE 257
#define INTERVAL 258
#define LISTEN 259
#define ON 260
#define ALL 261
#define PORT 262
#define USE 263
#define MAP 264
#define TYPE 265
#define HASH 266
#define LIST 267
#define SINGLE 268
#define SSL 269
#define SSMTP 270
#define CERTIFICATE 271
#define DNS 272
#define DB 273
#define TFILE 274
#define EXTERNAL 275
#define DOMAIN 276
#define CONFIG 277
#define SOURCE 278
#define RELAY 279
#define VIA 280
#define DELIVER 281
#define TO 282
#define MAILDIR 283
#define MBOX 284
#define HOSTNAME 285
#define ACCEPT 286
#define REJECT 287
#define INCLUDE 288
#define NETWORK 289
#define ERROR 290
#define MDA 291
#define FROM 292
#define FOR 293
#define ARROW 294
#define ENABLE 295
#define AUTH 296
#define TLS 297
#define STRING 298
#define NUMBER 299
#define YYERRCODE 256
short yylhs[] = {                                        -1,
    0,    0,    0,    0,    0,    0,    0,    0,   13,   14,
   17,   17,   17,   19,   19,   18,    2,    2,    2,    2,
   10,    4,    4,    4,   12,   12,    5,    5,    8,    8,
    8,    8,    7,    7,   15,   15,   15,   20,   20,   20,
   21,   21,   21,   21,   22,   22,   22,   23,   23,   24,
    1,   25,   26,   26,   27,   28,   28,   11,   29,   11,
   30,   11,   11,    3,    3,    9,    9,    9,   31,   31,
   32,   32,   33,   33,   33,   33,   33,    6,    6,    6,
   34,   16,
};
short yylen[] = {                                         2,
    0,    2,    3,    3,    3,    3,    3,    3,    2,    3,
    1,    1,    0,    2,    0,    2,    0,    1,    1,    1,
    2,    2,    2,    0,    3,    0,    1,    0,    1,    1,
    1,    0,    2,    0,    3,    7,    2,    1,    1,    1,
    1,    1,    2,    1,    2,    2,    2,    3,    2,    0,
    7,    3,    1,    3,    1,    1,    3,    1,    0,    4,
    0,    4,    2,    1,    1,    2,    2,    1,    3,    1,
    1,    3,    4,    4,    4,    1,    5,    2,    2,    0,
    0,    6,
};
short yydefred[] = {                                      1,
    0,    0,    0,    0,   27,    0,   64,   65,    0,    0,
    2,    0,    0,    0,    0,    0,    0,    0,    8,    0,
   50,   37,    9,    0,    6,    0,   81,    0,    3,    4,
    5,    7,    0,   35,    0,   10,   79,    0,   58,   61,
   59,   78,    0,    0,   18,   19,   20,   21,    0,   63,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   55,
    0,    0,   68,    0,    0,    0,   71,    0,    0,    0,
   14,    0,    0,    0,    0,    0,    0,    0,   11,    0,
   12,   62,    0,   60,   67,   66,    0,    0,    0,    0,
   82,   22,   23,    0,    0,   40,   39,   38,   45,   47,
   41,    0,   42,   44,   46,   49,   51,    0,   52,   16,
   54,   57,    0,   72,    0,    0,    0,    0,   36,   43,
   48,   69,   31,   29,   30,    0,    0,    0,    0,   25,
   33,    0,   73,   74,   75,   77,
};
short yydgoto[] = {                                       1,
   12,   48,   13,   70,   14,   27,  119,  126,   87,   34,
   42,   95,   15,   16,   17,   18,   80,   81,   56,   99,
  105,   75,   76,   35,   58,   59,   61,   62,   52,   51,
   88,   68,   91,   43,
};
short yysindex[] = {                                      0,
  -10,   13, -232, -246,    0, -245,    0,    0, -244,   -6,
    0,   46, -235, -201,   49,   50,   51,   52,    0, -236,
    0,    0,    0, -234,    0,  -37,    0, -195,    0,    0,
    0,    0,  -80,    0,  -57,    0,    0, -231,    0,    0,
    0,    0, -225, -229,    0,    0,    0,    0,   60,    0,
 -227, -226, -115, -189,   60, -250, -220,   -1,  -50,    0,
   -1,   35,    0,  -36,  -36, -251,    0, -260, -262, -186,
    0, -217, -219, -240,   60, -113, -218,   60,    0, -227,
    0,    0, -226,    0,    0,    0,   -1,  -47, -199, -200,
    0,    0,    0, -188, -211,    0,    0,    0,    0,    0,
    0, -213,    0,    0,    0,    0,    0,   78,    0,    0,
    0,    0, -251,    0, -253, -243, -209, -206,    0,    0,
    0,    0,    0,    0,    0, -207, -205, -204, -203,    0,
    0, -189,    0,    0,    0,    0,
};
short yyrindex[] = {                                      0,
 -201,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0, -197,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   82,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0, -247,    0,
    0,    0,    0,   -8, -120,    0,    0, -118,    0,    0,
  -35,    0,    0,    0,    0,    0,    0,    0,    0,   -9,
    0,    0,    0,    0, -111,    0,    0, -120,    0,    0,
    0,    0,    0,    0,    0,    0, -114,    0,   87,    0,
    0,    0,    0,    0,   88,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -198,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   89,    0,    0,    0,    0,
};
short yygindex[] = {                                      0,
    0,    0,    0,  -31,    0,    0,    0,    0,   53,    0,
  -18,    0,    0,    0,    0,    0,  -48,   -5,  -33,    0,
    0,   26,    0,    0,    0,   24,    0,   22,    0,    0,
   -4,    0,    0,    0,
};
#define YYTABLESIZE 288
short yytable[] = {                                      11,
   26,   24,   41,   41,   15,   56,   53,   66,   78,   63,
   70,  107,   83,   15,   72,  123,  124,   15,   89,   47,
   90,   71,   19,   46,   64,   20,   73,   74,   45,   15,
   15,  101,  102,  103,  104,   92,   93,   65,  113,  127,
  128,  106,   79,  125,  110,   85,   86,  129,   96,   97,
   98,   21,   22,   23,   24,   25,   26,   28,   29,   30,
   31,   32,   33,   36,   44,   49,   50,   53,   54,   55,
   57,   60,   69,   77,   82,   84,   94,  114,  100,  109,
  115,  116,  117,  118,  120,   40,   40,   78,  130,  131,
  132,   17,  133,  134,  135,   80,   76,   34,   24,   32,
  136,  108,  121,  111,  112,   67,    0,    0,  122,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   15,    0,    0,    0,   15,   63,   13,    0,    0,    0,
    0,   72,    0,   15,    0,   15,   15,   15,    0,    0,
   64,   13,    0,   73,   74,   15,   15,    0,   15,    0,
    0,    0,    0,   65,   13,    0,    0,   15,    0,   13,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   37,    0,    0,   38,   38,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    2,    3,    0,    0,    0,
    0,    0,    0,    4,   24,    0,    0,    0,    0,    5,
   39,   39,   13,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    6,    7,    8,    9,    0,    0,
    0,    0,    0,    0,    0,   26,   24,   10,
};
short yycheck[] = {                                      10,
   10,   10,   40,   40,  125,   41,  125,  123,   10,  261,
  125,  125,   61,  125,  265,  269,  270,  265,  279,  100,
  281,   55,   10,  104,  276,  258,  277,  278,  109,  277,
  278,  272,  273,  274,  275,  298,  299,  289,   87,  283,
  284,   75,   44,  297,   78,   64,   65,  291,  266,  267,
  268,  298,  298,  298,   61,   10,  292,  259,   10,   10,
   10,   10,  299,  298,  260,  123,  298,  293,  298,   10,
  298,  298,  262,  294,  125,   41,  263,  125,  298,  298,
  280,  282,  271,  295,  298,  123,  123,   10,  298,  296,
  298,   10,  298,  298,  298,  293,   10,   10,   10,  298,
  132,   76,  108,   80,   83,   53,   -1,   -1,  113,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  261,   -1,   -1,   -1,  265,  261,  261,   -1,   -1,   -1,
   -1,  265,   -1,  265,   -1,  276,  277,  278,   -1,   -1,
  276,  276,   -1,  277,  278,  277,  278,   -1,  289,   -1,
   -1,   -1,   -1,  289,  289,   -1,   -1,  298,   -1,  298,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  261,   -1,   -1,  264,  264,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  256,  257,   -1,   -1,   -1,
   -1,   -1,   -1,  264,  263,   -1,   -1,   -1,   -1,  270,
  298,  298,  298,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  285,  286,  287,  288,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  295,  295,  298,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 299
#if YYDEBUG
char *yyname[] = {
"end-of-file",0,0,0,0,0,0,0,0,0,"'\\n'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,"'('","')'",0,0,"','",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'='",0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'d'",
0,0,0,"'h'",0,0,0,0,"'m'",0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,"QUEUE","INTERVAL","LISTEN","ON","ALL","PORT","USE","MAP","TYPE","HASH",
"LIST","SINGLE","SSL","SSMTP","CERTIFICATE","DNS","DB","TFILE","EXTERNAL",
"DOMAIN","CONFIG","SOURCE","RELAY","VIA","DELIVER","TO","MAILDIR","MBOX",
"HOSTNAME","ACCEPT","REJECT","INCLUDE","NETWORK","ERROR","MDA","FROM","FOR",
"ARROW","ENABLE","AUTH","TLS","STRING","NUMBER",
};
char *yyrule[] = {
"$accept : grammar",
"grammar :",
"grammar : grammar '\\n'",
"grammar : grammar include '\\n'",
"grammar : grammar varset '\\n'",
"grammar : grammar main '\\n'",
"grammar : grammar map '\\n'",
"grammar : grammar rule '\\n'",
"grammar : grammar error '\\n'",
"include : INCLUDE STRING",
"varset : STRING '=' STRING",
"comma : ','",
"comma : nl",
"comma :",
"optnl : '\\n' optnl",
"optnl :",
"nl : '\\n' optnl",
"quantifier :",
"quantifier : 'm'",
"quantifier : 'h'",
"quantifier : 'd'",
"interval : NUMBER quantifier",
"port : PORT STRING",
"port : PORT NUMBER",
"port :",
"certname : USE CERTIFICATE STRING",
"certname :",
"ssmtp : SSMTP",
"ssmtp :",
"ssl : SSMTP",
"ssl : TLS",
"ssl : SSL",
"ssl :",
"auth : ENABLE AUTH",
"auth :",
"main : QUEUE INTERVAL interval",
"main : ssmtp LISTEN ON STRING port certname auth",
"main : HOSTNAME STRING",
"maptype : SINGLE",
"maptype : LIST",
"maptype : HASH",
"mapsource : DNS",
"mapsource : TFILE",
"mapsource : DB STRING",
"mapsource : EXTERNAL",
"mapopt : TYPE maptype",
"mapopt : SOURCE mapsource",
"mapopt : CONFIG STRING",
"mapopts_l : mapopts_l mapopt nl",
"mapopts_l : mapopt optnl",
"$$1 :",
"map : MAP STRING $$1 '{' optnl mapopts_l '}'",
"keyval : STRING ARROW STRING",
"keyval_list : keyval",
"keyval_list : keyval comma keyval_list",
"stringel : STRING",
"string_list : stringel",
"string_list : stringel comma string_list",
"mapref : STRING",
"$$2 :",
"mapref : '(' $$2 string_list ')'",
"$$3 :",
"mapref : '{' $$3 keyval_list '}'",
"mapref : MAP STRING",
"decision : ACCEPT",
"decision : REJECT",
"condition : NETWORK mapref",
"condition : DOMAIN mapref",
"condition : ALL",
"condition_list : condition comma condition_list",
"condition_list : condition",
"conditions : condition",
"conditions : '{' condition_list '}'",
"action : DELIVER TO MAILDIR STRING",
"action : DELIVER TO MBOX STRING",
"action : DELIVER TO MDA STRING",
"action : RELAY",
"action : RELAY VIA ssl STRING port",
"from : FROM mapref",
"from : FROM ALL",
"from :",
"$$4 :",
"rule : decision from $$4 FOR conditions action",
};
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 500
#define YYMAXDEPTH 500
#endif
#endif
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
short yyss[YYSTACKSIZE];
YYSTYPE yyvs[YYSTACKSIZE];
#define yystacksize YYSTACKSIZE
#line 826 "parse.y"

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
		{ "accept",		ACCEPT },
		{ "all",		ALL },
		{ "auth",		AUTH },
		{ "certificate",	CERTIFICATE },
		{ "config",		CONFIG },
		{ "db",			DB },
		{ "deliver",		DELIVER },
		{ "dns",		DNS },
		{ "domain",		DOMAIN },
		{ "enable",		ENABLE },
		{ "external",		EXTERNAL },
		{ "file",		TFILE },
		{ "for",		FOR },
		{ "from",		FROM },
		{ "hash",		HASH },
		{ "hostname",		HOSTNAME },
		{ "include",		INCLUDE },
		{ "interval",		INTERVAL },
		{ "list",		LIST },
		{ "listen",		LISTEN },
		{ "maildir",		MAILDIR },
		{ "map",		MAP },
		{ "mbox",		MBOX },
		{ "mda",		MDA },
		{ "network",		NETWORK },
		{ "on",			ON },
		{ "port",		PORT },
		{ "queue",		QUEUE },
		{ "reject",		REJECT },
		{ "relay",		RELAY },
		{ "single",		SINGLE },
		{ "source",		SOURCE },
		{ "ssl",		SSL },
		{ "ssmtp",		SSMTP },
		{ "tls",		TLS },
		{ "to",			TO },
		{ "type",		TYPE },
		{ "use",		USE },
		{ "via",		VIA },
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
				else if (next == '\n')
					continue;
				else
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
		log_warn("cannot stat %s", fname);
		return (-1);
	}
	if (st.st_uid != 0 && st.st_uid != getuid()) {
		log_warnx("%s: owner not root or current user", fname);
		return (-1);
	}
	if (st.st_mode & (S_IRWXG | S_IRWXO)) {
		log_warnx("%s: group/world readable/writeable", fname);
		return (-1);
	}
	return (0);
}

struct file *
pushfile(const char *name, int secret)
{
	struct file	*nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL ||
	    (nfile->name = strdup(name)) == NULL) {
		log_warn("malloc");
		return (NULL);
	}
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		log_warn("%s", nfile->name);
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

int
parse_config(struct smtpd *x_conf, const char *filename, int opts)
{
	struct sym	*sym, *next;

	conf = x_conf;
	bzero(conf, sizeof(*conf));
	if ((conf->sc_maps = calloc(1, sizeof(*conf->sc_maps))) == NULL ||
	    (conf->sc_rules = calloc(1, sizeof(*conf->sc_rules))) == NULL) {
		log_warn("cannot allocate memory");
		return 0;
	}

	errors = 0;
	last_map_id = 0;

	map = NULL;
	rule = NULL;

	TAILQ_INIT(&conf->sc_listeners);
	TAILQ_INIT(conf->sc_maps);
	TAILQ_INIT(conf->sc_rules);
	SPLAY_INIT(&conf->sc_sessions);
	SPLAY_INIT(&conf->sc_ssl);

	conf->sc_qintval.tv_sec = SMTPD_QUEUE_INTERVAL;
	conf->sc_qintval.tv_usec = 0;
	conf->sc_opts = opts;

	if ((file = pushfile(filename, 0)) == NULL) {
		purge_config(conf, PURGE_EVERYTHING);
		return (-1);
	}
	topfile = file;

	/*
	 * parse configuration
	 */
	setservent(1);
	yyparse();
	errors = file->errors;
	popfile();
	endservent();

	/* Free macros and check which have not been used. */
	for (sym = TAILQ_FIRST(&symhead); sym != NULL; sym = next) {
		next = TAILQ_NEXT(sym, entry);
		if ((conf->sc_opts & SMTPD_OPT_VERBOSE) && !sym->used)
			fprintf(stderr, "warning: macro '%s' not "
			    "used\n", sym->nam);
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	if (TAILQ_EMPTY(conf->sc_rules)) {
		log_warnx("no rules, nothing to do");
		errors++;
	}

	if (strlen(conf->sc_hostname) == 0)
		if (gethostname(conf->sc_hostname,
		    sizeof(conf->sc_hostname)) == -1) {
			log_warn("could not determine host name");
			bzero(conf->sc_hostname, sizeof(conf->sc_hostname));
			errors++;
		}

	if (errors) {
		purge_config(conf, PURGE_EVERYTHING);
		return (-1);
	}

	return (0);
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

struct listener *
host_v4(const char *s, in_port_t port)
{
	struct in_addr		 ina;
	struct sockaddr_in	*sain;
	struct listener		*h;

	bzero(&ina, sizeof(ina));
	if (inet_pton(AF_INET, s, &ina) != 1)
		return (NULL);

	if ((h = calloc(1, sizeof(*h))) == NULL)
		fatal(NULL);
	sain = (struct sockaddr_in *)&h->ss;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	sain->sin_len = sizeof(struct sockaddr_in);
#endif
	sain->sin_family = AF_INET;
	sain->sin_addr.s_addr = ina.s_addr;
	sain->sin_port = port;

	return (h);
}

struct listener *
host_v6(const char *s, in_port_t port)
{
	struct in6_addr		 ina6;
	struct sockaddr_in6	*sin6;
	struct listener		*h;

	bzero(&ina6, sizeof(ina6));
	if (inet_pton(AF_INET6, s, &ina6) != 1)
		return (NULL);

	if ((h = calloc(1, sizeof(*h))) == NULL)
		fatal(NULL);
	sin6 = (struct sockaddr_in6 *)&h->ss;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN6_LEN
	sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = port;
	memcpy(&sin6->sin6_addr, &ina6, sizeof(ina6));

	return (h);
}

int
host_dns(const char *s, struct listenerlist *al, int max, in_port_t port,
    u_int8_t flags)
{
	struct addrinfo		 hints, *res0, *res;
	int			 error, cnt = 0;
	struct sockaddr_in	*sain;
	struct sockaddr_in6	*sin6;
	struct listener		*h;

	bzero(&hints, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM; /* DUMMY */
	error = getaddrinfo(s, NULL, &hints, &res0);
	if (error == EAI_AGAIN || error == EAI_NODATA || error == EAI_NONAME)
		return (0);
	if (error) {
		log_warnx("host_dns: could not parse \"%s\": %s", s,
		    gai_strerror(error));
		return (-1);
	}

	for (res = res0; res && cnt < max; res = res->ai_next) {
		if (res->ai_family != AF_INET &&
		    res->ai_family != AF_INET6)
			continue;
		if ((h = calloc(1, sizeof(*h))) == NULL)
			fatal(NULL);

		h->port = port;
		h->flags = flags;
		h->ss.ss_family = res->ai_family;
		h->ssl = NULL;
		(void)strlcpy(h->ssl_cert_name, s, sizeof(h->ssl_cert_name));

		if (res->ai_family == AF_INET) {
			sain = (struct sockaddr_in *)&h->ss;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
			sain->sin_len = sizeof(struct sockaddr_in);
#endif
			sain->sin_addr.s_addr = ((struct sockaddr_in *)
			    res->ai_addr)->sin_addr.s_addr;
			sain->sin_port = port;
		} else {
			sin6 = (struct sockaddr_in6 *)&h->ss;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN6_LEN
			sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
			memcpy(&sin6->sin6_addr, &((struct sockaddr_in6 *)
			    res->ai_addr)->sin6_addr, sizeof(struct in6_addr));
			sin6->sin6_port = port;
		}

		TAILQ_INSERT_HEAD(al, h, entry);
		cnt++;
	}
	if (cnt == max && res) {
		log_warnx("host_dns: %s resolves to more than %d hosts",
		    s, max);
	}
	freeaddrinfo(res0);
	return (cnt);
}

int
host(const char *s, struct listenerlist *al, int max, in_port_t port,
    u_int8_t flags)
{
	struct listener *h;

	h = host_v4(s, port);

	/* IPv6 address? */
	if (h == NULL)
		h = host_v6(s, port);

	if (h != NULL) {
		h->port = port;
		h->flags = flags;
		h->ssl = NULL;
		(void)strlcpy(h->ssl_cert_name, s, sizeof(h->ssl_cert_name));

		TAILQ_INSERT_HEAD(al, h, entry);
		return (1);
	}

	return (host_dns(s, al, max, port, flags));
}

int
interface(const char *s, struct listenerlist *al, int max, in_port_t port,
    u_int8_t flags)
{
	struct ifaddrs *ifap, *p;
	struct sockaddr_in	*sain;
	struct sockaddr_in6	*sin6;
	struct listener		*h;
	int ret = 0;

	if (getifaddrs(&ifap) == -1)
		fatal("getifaddrs");

	for (p = ifap; p != NULL; p = p->ifa_next) {
		if (strcmp(s, p->ifa_name) != 0)
			continue;

		switch (p->ifa_addr->sa_family) {
		case AF_INET:
			if ((h = calloc(1, sizeof(*h))) == NULL)
				fatal(NULL);
			sain = (struct sockaddr_in *)&h->ss;
			*sain = *(struct sockaddr_in *)p->ifa_addr;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
			sain->sin_len = sizeof(struct sockaddr_in);
#endif
			sain->sin_port = port;

			h->port = port;
			h->flags = flags;
			h->ssl = NULL;
			(void)strlcpy(h->ssl_cert_name, s, sizeof(h->ssl_cert_name));

			ret = 1;
			TAILQ_INSERT_HEAD(al, h, entry);

			break;

		case AF_INET6:
			if ((h = calloc(1, sizeof(*h))) == NULL)
				fatal(NULL);
			sin6 = (struct sockaddr_in6 *)&h->ss;
			*sin6 = *(struct sockaddr_in6 *)p->ifa_addr;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN6_LEN
			sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
			sin6->sin6_port = port;

			h->port = port;
			h->flags = flags;
			h->ssl = NULL;
			(void)strlcpy(h->ssl_cert_name, s, sizeof(h->ssl_cert_name));

			ret = 1;
			TAILQ_INSERT_HEAD(al, h, entry);

			break;
		}
	}

	freeifaddrs(ifap);

	return ret;
}
#line 1166 "parse.c"
#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab
int
yyparse(void)
{
    register int yym, yyn, yystate;
#if YYDEBUG
    register char *yys;
    extern char *getenv();

    if (yys = getenv("YYDEBUG"))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yyssp >= yyss + yystacksize - 1)
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = (-1);
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;
#ifdef lint
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#ifdef lint
    goto yyerrlab;
#endif
yyerrlab:
    ++yynerrs;
yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yyss + yystacksize - 1)
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = (-1);
        goto yyloop;
    }
yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    yyval = yyvsp[1-yym];
    switch (yyn)
    {
case 8:
#line 141 "parse.y"
{ file->errors++; }
break;
case 9:
#line 144 "parse.y"
{
			struct file	*nfile;

			if ((nfile = pushfile(yyvsp[0].v.string, 0)) == NULL) {
				yyerror("failed to include file %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);

			file = nfile;
			lungetc('\n');
		}
break;
case 10:
#line 159 "parse.y"
{
			if (symset(yyvsp[-2].v.string, yyvsp[0].v.string, 0) == -1)
				fatal("cannot store variable");
			free(yyvsp[-2].v.string);
			free(yyvsp[0].v.string);
		}
break;
case 17:
#line 179 "parse.y"
{ yyval.v.number = 1; }
break;
case 18:
#line 180 "parse.y"
{ yyval.v.number = 60; }
break;
case 19:
#line 181 "parse.y"
{ yyval.v.number = 3600; }
break;
case 20:
#line 182 "parse.y"
{ yyval.v.number = 86400; }
break;
case 21:
#line 185 "parse.y"
{
			if (yyvsp[-1].v.number < 0) {
				yyerror("invalid interval: %lld", yyvsp[-1].v.number);
				YYERROR;
			}
			yyval.v.tv.tv_usec = 0;
			yyval.v.tv.tv_sec = yyvsp[-1].v.number * yyvsp[0].v.number;
		}
break;
case 22:
#line 194 "parse.y"
{
			struct servent	*servent;

			servent = getservbyname(yyvsp[0].v.string, "tcp");
			if (servent == NULL) {
				yyerror("port %s is invalid", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			yyval.v.number = servent->s_port;
			free(yyvsp[0].v.string);
		}
break;
case 23:
#line 206 "parse.y"
{
			if (yyvsp[0].v.number <= 0 || yyvsp[0].v.number >= (int)USHRT_MAX) {
				yyerror("invalid port: %lld", yyvsp[0].v.number);
				YYERROR;
			}
			yyval.v.number = htons(yyvsp[0].v.number);
		}
break;
case 24:
#line 213 "parse.y"
{
			yyval.v.number = 0;
		}
break;
case 25:
#line 218 "parse.y"
{
			if ((yyval.v.string = strdup(yyvsp[0].v.string)) == NULL)
				fatal(NULL);
			free(yyvsp[0].v.string);
		}
break;
case 26:
#line 223 "parse.y"
{ yyval.v.string = NULL; }
break;
case 27:
#line 226 "parse.y"
{ yyval.v.number = 1; }
break;
case 28:
#line 227 "parse.y"
{ yyval.v.number = 0; }
break;
case 29:
#line 230 "parse.y"
{ yyval.v.number = F_SSMTP; }
break;
case 30:
#line 231 "parse.y"
{ yyval.v.number = F_STARTTLS; }
break;
case 31:
#line 232 "parse.y"
{ yyval.v.number = F_SSL; }
break;
case 32:
#line 233 "parse.y"
{ yyval.v.number = 0; }
break;
case 33:
#line 235 "parse.y"
{ yyval.v.number = 1; }
break;
case 34:
#line 236 "parse.y"
{ yyval.v.number = 0; }
break;
case 35:
#line 239 "parse.y"
{
			conf->sc_qintval = yyvsp[0].v.tv;
		}
break;
case 36:
#line 242 "parse.y"
{
			char		*cert;
			u_int8_t	 flags;

			if (yyvsp[-2].v.number == 0) {
				if (yyvsp[-6].v.number)
					yyvsp[-2].v.number = 487;
				else
					yyvsp[-2].v.number = 25;
			}
			cert = (yyvsp[-1].v.string != NULL) ? yyvsp[-1].v.string : yyvsp[-3].v.string;

			flags = 0;

			if (yyvsp[0].v.number)
				flags |= F_AUTH;

			if (ssl_load_certfile(conf, cert) < 0) {
				log_warnx("warning: could not load cert: %s, "
				    "no SSL/TLS/AUTH support", cert);
				if (yyvsp[-6].v.number || yyvsp[-1].v.string != NULL) {
					yyerror("cannot load certificate: %s",
					    cert);
					free(yyvsp[-1].v.string);
					free(yyvsp[-3].v.string);
					YYERROR;
				}
			}
			else {
				if (yyvsp[-6].v.number)
					flags |= F_SSMTP;
				else
					flags |= F_STARTTLS;
			}

			if (! interface(yyvsp[-3].v.string, &conf->sc_listeners,
				MAX_LISTEN, yyvsp[-2].v.number, flags)) {
				if (host(yyvsp[-3].v.string, &conf->sc_listeners,
					MAX_LISTEN, yyvsp[-2].v.number, flags) <= 0) {
					yyerror("invalid virtual ip or interface: %s", yyvsp[-3].v.string);
					free(yyvsp[-1].v.string);
					free(yyvsp[-3].v.string);
					YYERROR;
				}
			}
			free(yyvsp[-1].v.string);
			free(yyvsp[-3].v.string);
		}
break;
case 37:
#line 290 "parse.y"
{
			if (strlcpy(conf->sc_hostname, yyvsp[0].v.string,
			    sizeof(conf->sc_hostname)) >=
			    sizeof(conf->sc_hostname)) {
				yyerror("hostname truncated");
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
		}
break;
case 38:
#line 302 "parse.y"
{ map->m_type = T_SINGLE; }
break;
case 39:
#line 303 "parse.y"
{ map->m_type = T_LIST; }
break;
case 40:
#line 304 "parse.y"
{ map->m_type = T_HASH; }
break;
case 41:
#line 307 "parse.y"
{ map->m_src = S_DNS; }
break;
case 42:
#line 308 "parse.y"
{ map->m_src = S_FILE; }
break;
case 43:
#line 309 "parse.y"
{
			map->m_src = S_DB;
			if (strlcpy(map->m_config, yyvsp[0].v.string, sizeof(map->m_config))
			    >= sizeof(map->m_config))
				err(1, "pathname too long");
		}
break;
case 44:
#line 315 "parse.y"
{ map->m_src = S_EXT; }
break;
case 47:
#line 320 "parse.y"
{
		}
break;
case 50:
#line 328 "parse.y"
{
			struct map	*m;

			TAILQ_FOREACH(m, conf->sc_maps, m_entry)
				if (strcmp(m->m_name, yyvsp[0].v.string) == 0)
					break;

			if (m != NULL) {
				yyerror("map %s defined twice", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			if ((m = calloc(1, sizeof(*m))) == NULL)
				fatal("out of memory");
			if (strlcpy(m->m_name, yyvsp[0].v.string, sizeof(m->m_name)) >=
			    sizeof(m->m_name)) {
				yyerror("map name truncated");
				free(m);
				free(yyvsp[0].v.string);
				YYERROR;
			}

			m->m_id = last_map_id++;
			m->m_type = T_SINGLE;

			if (m->m_id == INT_MAX) {
				yyerror("too many maps defined");
				free(yyvsp[0].v.string);
				free(m);
				YYERROR;
			}
			map = m;
		}
break;
case 51:
#line 360 "parse.y"
{
			if (map->m_src == S_NONE) {
				yyerror("map %s has no source defined", yyvsp[-5].v.string);
				free(map);
				map = NULL;
				YYERROR;
			}
			if (strcmp(map->m_name, "aliases") == 0 ||
			    strcmp(map->m_name, "virtual") == 0) {
				if (map->m_src != S_DB) {
					yyerror("map source must be db");
					free(map);
					map = NULL;
					YYERROR;
				}
			}
			TAILQ_INSERT_TAIL(conf->sc_maps, map, m_entry);
			map = NULL;
		}
break;
case 52:
#line 381 "parse.y"
{
			struct mapel	*me;

			if ((me = calloc(1, sizeof(*me))) == NULL)
				fatal("out of memory");

			if (strlcpy(me->me_key.med_string, yyvsp[-2].v.string,
			    sizeof(me->me_key.med_string)) >=
			    sizeof(me->me_key.med_string) ||
			    strlcpy(me->me_val.med_string, yyvsp[0].v.string,
			    sizeof(me->me_val.med_string)) >=
			    sizeof(me->me_val.med_string)) {
				yyerror("map elements too long: %s, %s",
				    yyvsp[-2].v.string, yyvsp[0].v.string);
				free(me);
				free(yyvsp[-2].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[-2].v.string);
			free(yyvsp[0].v.string);

			TAILQ_INSERT_TAIL(contents, me, me_entry);
		}
break;
case 55:
#line 410 "parse.y"
{
			struct mapel	*me;
			int bits;
			struct sockaddr_in ssin;
			struct sockaddr_in6 ssin6;

			if ((me = calloc(1, sizeof(*me))) == NULL)
				fatal("out of memory");

			/* Attempt detection of $1 format */
			if (strchr(yyvsp[0].v.string, '/') != NULL) {
				/* Dealing with a netmask */
				bzero(&ssin, sizeof(struct sockaddr_in));
				bits = inet_net_pton(AF_INET, yyvsp[0].v.string, &ssin.sin_addr, sizeof(struct in_addr));
				if (bits != -1) {
					ssin.sin_family = AF_INET;
					me->me_key.med_addr.bits = bits;
					me->me_key.med_addr.ss = *(struct sockaddr_storage *)&ssin;
				}
				else {
					bzero(&ssin6, sizeof(struct sockaddr_in6));
					bits = inet_net_pton(AF_INET6, yyvsp[0].v.string, &ssin6.sin6_addr, sizeof(struct in6_addr));
					if (bits == -1)
						err(1, "inet_net_pton");
					ssin6.sin6_family = AF_INET6;
					me->me_key.med_addr.bits = bits;
					me->me_key.med_addr.ss = *(struct sockaddr_storage *)&ssin6;
				}
			}
			else {
				/* IP address ? */
				if (inet_pton(AF_INET, yyvsp[0].v.string, &ssin.sin_addr) == 1) {
					ssin.sin_family = AF_INET;
					me->me_key.med_addr.bits = 0;
					me->me_key.med_addr.ss = *(struct sockaddr_storage *)&ssin;
				}
				else if (inet_pton(AF_INET6, yyvsp[0].v.string, &ssin6.sin6_addr) == 1) {
					ssin6.sin6_family = AF_INET6;
					me->me_key.med_addr.bits = 0;
					me->me_key.med_addr.ss = *(struct sockaddr_storage *)&ssin6;
				}
				else {
					/* either a hostname or a value unrelated to network */
					if (strlcpy(me->me_key.med_string, yyvsp[0].v.string,
						sizeof(me->me_key.med_string)) >=
					    sizeof(me->me_key.med_string)) {
						yyerror("map element too long: %s", yyvsp[0].v.string);
						free(me);
						free(yyvsp[0].v.string);
						YYERROR;
					}
				}
			}
			free(yyvsp[0].v.string);
			TAILQ_INSERT_TAIL(contents, me, me_entry);
		}
break;
case 58:
#line 472 "parse.y"
{
			struct map	*m;
			struct mapel	*me;
			int bits;
			struct sockaddr_in ssin;
			struct sockaddr_in6 ssin6;

			if ((m = calloc(1, sizeof(*m))) == NULL)
				fatal("out of memory");
			m->m_id = last_map_id++;
			if (m->m_id == INT_MAX) {
				yyerror("too many maps defined");
				free(m);
				YYERROR;
			}
			if (! bsnprintf(m->m_name, sizeof(m->m_name),
				"<dynamic(%u)>", m->m_id))
				fatal("snprintf");
			m->m_flags |= F_DYNAMIC|F_USED;
			m->m_type = T_SINGLE;

			TAILQ_INIT(&m->m_contents);

			if ((me = calloc(1, sizeof(*me))) == NULL)
				fatal("out of memory");

			/* Attempt detection of $1 format */
			if (strchr(yyvsp[0].v.string, '/') != NULL) {
				/* Dealing with a netmask */
				bzero(&ssin, sizeof(struct sockaddr_in));
				bits = inet_net_pton(AF_INET, yyvsp[0].v.string, &ssin.sin_addr, sizeof(struct in_addr));
				if (bits != -1) {
					ssin.sin_family = AF_INET;
					me->me_key.med_addr.bits = bits;
					me->me_key.med_addr.ss = *(struct sockaddr_storage *)&ssin;
				}
				else {
					bzero(&ssin6, sizeof(struct sockaddr_in6));
					bits = inet_net_pton(AF_INET6, yyvsp[0].v.string, &ssin6.sin6_addr, sizeof(struct in6_addr));
					if (bits == -1)
						err(1, "inet_net_pton");
					ssin6.sin6_family = AF_INET6;
					me->me_key.med_addr.bits = bits;
					me->me_key.med_addr.ss = *(struct sockaddr_storage *)&ssin6;
				}
			}
			else {
				/* IP address ? */
				if (inet_pton(AF_INET, yyvsp[0].v.string, &ssin.sin_addr) == 1) {
					ssin.sin_family = AF_INET;
					me->me_key.med_addr.bits = 0;
					me->me_key.med_addr.ss = *(struct sockaddr_storage *)&ssin;
				}
				else if (inet_pton(AF_INET6, yyvsp[0].v.string, &ssin6.sin6_addr) == 1) {
					ssin6.sin6_family = AF_INET6;
					me->me_key.med_addr.bits = 0;
					me->me_key.med_addr.ss = *(struct sockaddr_storage *)&ssin6;
				}
				else {
					/* either a hostname or a value unrelated to network */
					if (strlcpy(me->me_key.med_string, yyvsp[0].v.string,
						sizeof(me->me_key.med_string)) >=
					    sizeof(me->me_key.med_string)) {
						yyerror("map element too long: %s", yyvsp[0].v.string);
						free(me);
						free(m);
						free(yyvsp[0].v.string);
						YYERROR;
					}
				}
			}
			free(yyvsp[0].v.string);

			TAILQ_INSERT_TAIL(&m->m_contents, me, me_entry);
			TAILQ_INSERT_TAIL(conf->sc_maps, m, m_entry);
			yyval.v.object = m->m_id;
		}
break;
case 59:
#line 549 "parse.y"
{
			struct map	*m;

			if ((m = calloc(1, sizeof(*m))) == NULL)
				fatal("out of memory");

			m->m_id = last_map_id++;
			if (m->m_id == INT_MAX) {
				yyerror("too many maps defined");
				free(m);
				YYERROR;
			}
			if (! bsnprintf(m->m_name, sizeof(m->m_name),
				"<dynamic(%u)>", m->m_id))
				fatal("snprintf");
			m->m_flags |= F_DYNAMIC|F_USED;
			m->m_type = T_LIST;

			TAILQ_INIT(&m->m_contents);
			contents = &m->m_contents;
			map = m;

		}
break;
case 60:
#line 571 "parse.y"
{
			TAILQ_INSERT_TAIL(conf->sc_maps, map, m_entry);
			yyval.v.object = map->m_id;
		}
break;
case 61:
#line 575 "parse.y"
{
			struct map	*m;

			if ((m = calloc(1, sizeof(*m))) == NULL)
				fatal("out of memory");

			m->m_id = last_map_id++;
			if (m->m_id == INT_MAX) {
				yyerror("too many maps defined");
				free(m);
				YYERROR;
			}
			if (! bsnprintf(m->m_name, sizeof(m->m_name),
				"<dynamic(%u)>", m->m_id))
				fatal("snprintf");
			m->m_flags |= F_DYNAMIC|F_USED;
			m->m_type = T_HASH;

			TAILQ_INIT(&m->m_contents);
			contents = &m->m_contents;
			map = m;

		}
break;
case 62:
#line 597 "parse.y"
{
			TAILQ_INSERT_TAIL(conf->sc_maps, map, m_entry);
			yyval.v.object = map->m_id;
		}
break;
case 63:
#line 601 "parse.y"
{
			struct map	*m;

			if ((m = map_findbyname(conf, yyvsp[0].v.string)) == NULL) {
				yyerror("no such map: %s", yyvsp[0].v.string);
				free(yyvsp[0].v.string);
				YYERROR;
			}
			free(yyvsp[0].v.string);
			m->m_flags |= F_USED;
			yyval.v.object = m->m_id;
		}
break;
case 64:
#line 615 "parse.y"
{ yyval.v.number = 1; }
break;
case 65:
#line 616 "parse.y"
{ yyval.v.number = 0; }
break;
case 66:
#line 619 "parse.y"
{
			struct cond	*c;

			if ((c = calloc(1, sizeof *c)) == NULL)
				fatal("out of memory");
			c->c_type = C_NET;
			c->c_map = yyvsp[0].v.object;
			yyval.v.cond = c;
		}
break;
case 67:
#line 628 "parse.y"
{
			struct cond	*c;

			if ((c = calloc(1, sizeof *c)) == NULL)
				fatal("out of memory");
			c->c_type = C_DOM;
			c->c_map = yyvsp[0].v.object;
			yyval.v.cond = c;
		}
break;
case 68:
#line 637 "parse.y"
{
			struct cond	*c;

			if ((c = calloc(1, sizeof *c)) == NULL)
				fatal("out of memory");
			c->c_type = C_ALL;
			yyval.v.cond = c;
		}
break;
case 69:
#line 647 "parse.y"
{
			TAILQ_INSERT_TAIL(&rule->r_conditions, yyvsp[-2].v.cond, c_entry);
		}
break;
case 70:
#line 650 "parse.y"
{
			TAILQ_INSERT_TAIL(&rule->r_conditions, yyvsp[0].v.cond, c_entry);
		}
break;
case 71:
#line 655 "parse.y"
{
			TAILQ_INSERT_TAIL(&rule->r_conditions, yyvsp[0].v.cond, c_entry);
		}
break;
case 73:
#line 661 "parse.y"
{
			rule->r_action = A_MAILDIR;
			if (strlcpy(rule->r_value.path, yyvsp[0].v.string,
			    sizeof(rule->r_value.path)) >=
			    sizeof(rule->r_value.path))
				fatal("pathname too long");
			free(yyvsp[0].v.string);
		}
break;
case 74:
#line 669 "parse.y"
{
			rule->r_action = A_MBOX;
			if (strlcpy(rule->r_value.path, yyvsp[0].v.string,
			    sizeof(rule->r_value.path))
			    >= sizeof(rule->r_value.path))
				fatal("pathname too long");
			free(yyvsp[0].v.string);
		}
break;
case 75:
#line 677 "parse.y"
{
			rule->r_action = A_EXT;
			if (strlcpy(rule->r_value.command, yyvsp[0].v.string,
			    sizeof(rule->r_value.command))
			    >= sizeof(rule->r_value.command))
				fatal("command too long");
			free(yyvsp[0].v.string);
		}
break;
case 76:
#line 685 "parse.y"
{
			rule->r_action = A_RELAY;
		}
break;
case 77:
#line 688 "parse.y"
{
			rule->r_action = A_RELAYVIA;

			if (yyvsp[-2].v.number)
				rule->r_value.relayhost.flags = yyvsp[-2].v.number;

			if (strlcpy(rule->r_value.relayhost.hostname, yyvsp[-1].v.string,
			    sizeof(rule->r_value.relayhost.hostname))
			    >= sizeof(rule->r_value.relayhost.hostname))
				fatal("hostname too long");

			if (yyvsp[0].v.number == 0)
				rule->r_value.relayhost.port = 0;
			else
				rule->r_value.relayhost.port = yyvsp[0].v.number;

			free(yyvsp[-1].v.string);
		}
break;
case 78:
#line 708 "parse.y"
{
			yyval.v.number = yyvsp[0].v.object;
		}
break;
case 79:
#line 711 "parse.y"
{
			struct map	*m;
			struct mapel	*me;
			struct sockaddr_in *ssin;
			struct sockaddr_in6 *ssin6;

			if ((m = calloc(1, sizeof(*m))) == NULL)
				fatal("out of memory");
			m->m_id = last_map_id++;
			if (m->m_id == INT_MAX) {
				yyerror("too many maps defined");
				free(m);
				YYERROR;
			}
			if (! bsnprintf(m->m_name, sizeof(m->m_name),
				"<dynamic(%u)>", m->m_id))
				fatal("snprintf");
			m->m_flags |= F_DYNAMIC|F_USED;
			m->m_type = T_SINGLE;

			TAILQ_INIT(&m->m_contents);

			if ((me = calloc(1, sizeof(*me))) == NULL)
				fatal("out of memory");
			me->me_key.med_addr.bits = 32;
			ssin = (struct sockaddr_in *)&me->me_key.med_addr.ss;
			ssin->sin_family = AF_INET;
			if (inet_pton(AF_INET, "0.0.0.0", &ssin->sin_addr) != 1) {
				free(me);
				free(m);
				YYERROR;
			}
			TAILQ_INSERT_TAIL(&m->m_contents, me, me_entry);

			if ((me = calloc(1, sizeof(*me))) == NULL)
				fatal("out of memory");
			me->me_key.med_addr.bits = 128;
			ssin6 = (struct sockaddr_in6 *)&me->me_key.med_addr.ss;
			ssin6->sin6_family = AF_INET6;
			if (inet_pton(AF_INET6, "::", &ssin6->sin6_addr) != 1) {
				free(me);
				free(m);
				YYERROR;
			}
			TAILQ_INSERT_TAIL(&m->m_contents, me, me_entry);

			TAILQ_INSERT_TAIL(conf->sc_maps, m, m_entry);
			yyval.v.number = m->m_id;
		}
break;
case 80:
#line 760 "parse.y"
{
			struct map	*m;
			struct mapel	*me;
			struct sockaddr_in *ssin;
			struct sockaddr_in6 *ssin6;

			if ((m = calloc(1, sizeof(*m))) == NULL)
				fatal("out of memory");
			m->m_id = last_map_id++;
			if (m->m_id == INT_MAX) {
				yyerror("too many maps defined");
				free(m);
				YYERROR;
			}
			if (! bsnprintf(m->m_name, sizeof(m->m_name),
				"<dynamic(%u)>", m->m_id))
				fatal("snprintf");
			m->m_flags |= F_DYNAMIC|F_USED;
			m->m_type = T_SINGLE;

			TAILQ_INIT(&m->m_contents);

			if ((me = calloc(1, sizeof(*me))) == NULL)
				fatal("out of memory");
			me->me_key.med_addr.bits = 0;
			ssin = (struct sockaddr_in *)&me->me_key.med_addr.ss;
			ssin->sin_family = AF_INET;
			if (inet_pton(AF_INET, "127.0.0.1", &ssin->sin_addr) != 1) {
				free(me);
				free(m);
				YYERROR;
			}
			TAILQ_INSERT_TAIL(&m->m_contents, me, me_entry);

			if ((me = calloc(1, sizeof(*me))) == NULL)
				fatal("out of memory");
			me->me_key.med_addr.bits = 0;
			ssin6 = (struct sockaddr_in6 *)&me->me_key.med_addr.ss;
			ssin6->sin6_family = AF_INET6;
			if (inet_pton(AF_INET6, "::1", &ssin6->sin6_addr) != 1) {
				free(me);
				free(m);
				YYERROR;
			}
			TAILQ_INSERT_TAIL(&m->m_contents, me, me_entry);

			TAILQ_INSERT_TAIL(conf->sc_maps, m, m_entry);
			yyval.v.number = m->m_id;
		}
break;
case 81:
#line 811 "parse.y"
{
			struct rule	*r;

			if ((r = calloc(1, sizeof(*r))) == NULL)
				fatal("out of memory");
			rule = r;
			rule->r_sources = map_find(conf, yyvsp[0].v.number);
			TAILQ_INIT(&rule->r_conditions);
			TAILQ_INIT(&rule->r_options);

		}
break;
case 82:
#line 821 "parse.y"
{
			TAILQ_INSERT_TAIL(conf->sc_rules, rule, r_entry);
		}
break;
#line 2102 "parse.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yyss + yystacksize - 1)
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;
yyoverflow:
    yyerror("yacc stack overflow");
yyabort:
    return (1);
yyaccept:
    return (0);
}
