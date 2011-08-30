#ifndef lint
static const char yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93";
#endif

#include <stdlib.h>
#include <string.h>

#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYPATCH 20100216

#define YYEMPTY        (-1)
#define yyclearin      (yychar = YYEMPTY)
#define yyerrok        (yyerrflag = 0)
#define YYRECOVERING() (yyerrflag != 0)

#define YYPREFIX "yy"

/* compatibility with bison */
#ifdef YYPARSE_PARAM
/* compatibility with FreeBSD */
#ifdef YYPARSE_PARAM_TYPE
#define YYPARSE_DECL() yyparse(YYPARSE_PARAM_TYPE YYPARSE_PARAM)
#else
#define YYPARSE_DECL() yyparse(void *YYPARSE_PARAM)
#endif
#else
#define YYPARSE_DECL() yyparse(void)
#endif /* YYPARSE_PARAM */

extern int YYPARSE_DECL();

#line 25 "parse.y"
#include <sys/types.h>
#include <sys/time.h>
#include "sys-queue.h"
#include "sys-tree.h"
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <ifaddrs.h>
#include "imsg.h"
#include <paths.h>
#include <pwd.h>
/* need to define __USE_GNU to get EAI_NODATA defined */
#define __USE_GNU
#include <netdb.h>
#undef __USE_GNU
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#ifdef HAVE_UTIL_H
#include <util.h>
#endif

#include "defines.h"
#include "smtpd.h"
#include "log.h"

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

objid_t			 last_map_id = 1;
struct map		*map = NULL;
struct rule		*rule = NULL;
TAILQ_HEAD(condlist, cond) *conditions = NULL;
struct mapel_list	*contents = NULL;

struct listener	*host_v4(const char *, in_port_t);
struct listener	*host_v6(const char *, in_port_t);
int		 host_dns(const char *, const char *, const char *,
		    struct listenerlist *, int, in_port_t, u_int8_t);
int		 host(const char *, const char *, const char *,
		    struct listenerlist *, int, in_port_t, u_int8_t);
int		 interface(const char *, const char *, const char *,
		    struct listenerlist *, int, in_port_t, u_int8_t);
void		 set_localaddrs(void);
int		 delaytonum(char *);
int		 is_if_in_group(const char *, const char *);

typedef struct {
	union {
		int64_t		 number;
		objid_t		 object;
		struct timeval	 tv;
		struct cond	*cond;
		char		*string;
		struct host	*host;
		struct mailaddr	*maddr;
	} v;
	int lineno;
} YYSTYPE;

#line 137 "parse.c"
#define AS 257
#define QUEUE 258
#define INTERVAL 259
#define SIZE 260
#define LISTEN 261
#define ON 262
#define ALL 263
#define PORT 264
#define EXPIRE 265
#define MAP 266
#define TYPE 267
#define HASH 268
#define LIST 269
#define SINGLE 270
#define SSL 271
#define SMTPS 272
#define CERTIFICATE 273
#define DNS 274
#define DB 275
#define PLAIN 276
#define EXTERNAL 277
#define DOMAIN 278
#define CONFIG 279
#define SOURCE 280
#define RELAY 281
#define VIA 282
#define DELIVER 283
#define TO 284
#define MAILDIR 285
#define MBOX 286
#define HOSTNAME 287
#define ACCEPT 288
#define REJECT 289
#define INCLUDE 290
#define NETWORK 291
#define ERROR 292
#define MDA 293
#define FROM 294
#define FOR 295
#define ARROW 296
#define ENABLE 297
#define AUTH 298
#define TLS 299
#define LOCAL 300
#define VIRTUAL 301
#define TAG 302
#define ALIAS 303
#define FILTER 304
#define STRING 305
#define NUMBER 306
#define YYERRCODE 256
static const short yylhs[] = {                           -1,
    0,    0,    0,    0,    0,    0,    0,    0,   20,   21,
   24,   24,   24,   26,   26,   25,    2,    2,    2,    2,
   12,    8,    8,    4,    4,    4,   15,   15,    7,    7,
    7,    7,    6,    6,   17,   17,    9,    9,   10,   10,
   22,   22,   22,   22,   22,   27,   27,   27,   28,   28,
   28,   28,   29,   29,   29,   30,   30,   31,    1,   32,
   33,   33,   34,   35,   35,   13,   36,   13,   37,   13,
   13,    3,    3,   19,   19,   11,   11,   11,   11,   11,
   38,   38,   39,   39,   16,   16,   14,   14,   40,   40,
   40,   40,   40,   40,    5,    5,    5,    5,   18,   18,
   41,   23,
};
static const short yylen[] = {                            2,
    0,    2,    3,    3,    3,    3,    3,    3,    2,    3,
    1,    1,    0,    2,    0,    2,    0,    1,    1,    1,
    2,    1,    1,    2,    2,    0,    2,    0,    1,    1,
    1,    0,    2,    0,    2,    0,    2,    0,    2,    0,
    3,    2,    2,    8,    2,    1,    1,    1,    1,    2,
    2,    1,    2,    2,    2,    3,    2,    0,    7,    3,
    1,    3,    1,    1,    3,    1,    0,    4,    0,    4,
    2,    1,    1,    2,    0,    2,    3,    2,    2,    2,
    3,    1,    1,    3,    2,    0,    2,    0,    4,    5,
    3,    5,    2,    8,    2,    2,    2,    0,    2,    0,
    0,    9,
};
static const short yydefred[] = {                         1,
    0,    0,    0,    0,    0,    0,    0,    0,   72,   73,
    0,    0,    2,    0,    0,    0,    0,    0,    0,    8,
    0,   23,   22,   43,    0,   42,   58,   45,    9,    0,
    6,    0,    0,    3,    4,    5,    7,    0,   41,    0,
    0,   10,   99,    0,  101,   18,   19,   20,   21,    0,
    0,    0,   96,    0,   97,   66,   69,   67,   95,    0,
   24,   25,   31,   29,   30,    0,    0,    0,   71,    0,
    0,    0,    0,    0,   14,    0,    0,    0,    0,    0,
    0,    0,    0,   63,    0,    0,    0,    0,    0,    0,
    0,    0,   83,    0,   27,    0,    0,   48,   47,   46,
   53,   55,   49,    0,    0,   52,   54,   57,   59,    0,
    0,    0,   11,    0,   12,   70,    0,   68,    0,   80,
    0,   76,   79,   78,    0,    0,    0,    0,    0,   33,
    0,   44,   51,   50,   56,   60,   16,   62,   65,   74,
   77,    0,   84,    0,    0,   93,    0,    0,   35,   81,
   87,    0,    0,   91,    0,    0,  102,    0,    0,    0,
   89,    0,   37,    0,   85,   90,   92,    0,    0,    0,
   39,   94,
};
static const short yydgoto[] = {                          1,
   14,   49,   15,   51,   45,   97,   66,   24,  157,  170,
  125,   39,   59,  146,   74,  161,  132,   33,  120,   16,
   17,   18,   19,  114,  115,   68,  101,  107,   79,   80,
   41,   82,   83,   85,   86,   71,   70,  126,   94,  129,
   60,
};
static const short yysindex[] = {                         0,
  -10,   19, -225, -262, -222, -268, -231, -227,    0,    0,
 -224,   10,    0,   72, -179,   74,   75,   76,   77,    0,
 -217,    0,    0,    0, -214,    0,    0,    0,    0, -213,
    0, -210, -206,    0,    0,    0,    0,  -62,    0, -170,
  -27,    0,    0,  -19,    0,    0,    0,    0,    0, -257,
 -241,   87,    0, -207,    0,    0,    0,    0,    0, -196,
    0,    0,    0,    0,    0, -173,   87, -234,    0, -204,
 -203, -116, -202, -192,    0, -209, -199, -208,   87,  -93,
 -189,   13,  -17,    0,   13,   68, -193,  -30,  -30, -193,
 -194, -237,    0, -211,    0, -186, -188,    0,    0,    0,
    0,    0,    0, -190, -187,    0,    0,    0,    0,  103,
 -185,   87,    0, -204,    0,    0, -203,    0, -184,    0,
 -193,    0,    0,    0,   13,   -6, -232, -168, -188,    0,
 -183,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, -237,    0, -182, -181,    0, -258, -148,    0,    0,
    0, -170, -240,    0, -180, -178,    0, -241, -177, -131,
    0, -131,    0, -173,    0,    0,    0, -169, -175, -126,
    0,    0,
};
static const short yyrindex[] = {                         0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0, -218,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0, -163,    0,    0,    0,    0,  123,    0,   -1,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    3, -228,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    5, -124,    0,    0,    0,
    0,    0,    0,    6,    0,    0,    0,    0,  -89,    0,
    0, -122,    0,    0,  -22,    0,   46,    0,    0,   46,
    0,    0,    0,    0,    0,    0,   76,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0, -124,    0,    0,    0,    0,    0,    0,    0,    0,
   46,    0,    0,    0, -121,    0,    4,    0,   -4,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  124,    0,    0,
    0,   -8,    8,    0,    0,    0,    0,   -5,    0,    8,
    0,    8,    0,    1,    0,    0,    0,    2,    0,    4,
    0,    0,
};
static const short yygindex[] = {                         0,
    0,    0,    0,  -16,    0,    0,  -23,    0,    0,    0,
   65,    0,   -9,  -32,  -24,  -87,   12,    0,  -66,    0,
    0,    0,    0,  -63,   34,  -59,    0,    0,   66,    0,
    0,    0,   31,    0,   32,    0,    0,    9,    0,    0,
    0,
};
#define YYTABLESIZE 347
static const short yytable[] = {                         13,
   15,   26,   61,   82,   32,   36,   92,   75,   26,   58,
   28,   40,   32,   88,   28,   34,  159,   86,   64,  108,
   58,  117,  112,  123,  144,   87,  153,  154,   20,   63,
   64,  109,   76,   21,  155,   15,   26,   48,   15,   25,
   88,   47,   22,   23,   77,   78,   46,   61,   62,  145,
   15,   15,  137,   89,  141,   75,  113,   65,   98,   99,
  100,  142,   90,   91,  160,  103,  104,  105,  106,  127,
   30,  128,  166,   27,  167,  100,  100,   28,  121,  122,
   29,   31,   32,   34,   35,   36,   37,   44,   38,   75,
   40,   42,   57,   50,   43,   52,   67,   69,   72,   73,
   81,   84,   95,   57,   96,  102,  111,  116,  118,  119,
  124,  130,  112,  131,  133,  147,  156,  134,  143,  136,
  140,  149,  151,  152,  162,  159,  163,  165,  169,  171,
  144,   98,   17,   38,  164,  158,   93,  172,   15,  168,
  148,   13,   15,  135,  138,  110,   87,    0,  139,    0,
  150,    0,    0,   15,   15,   15,   13,    0,    0,    0,
    0,   88,    0,    0,    0,    0,   15,    0,    0,   13,
   75,    0,    0,   76,   89,   15,   15,   15,   13,   13,
   15,    0,   13,   90,   91,   77,   78,    0,    0,   15,
   15,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   54,    0,    0,    0,    0,
    0,    0,    0,   53,    0,    2,   54,    3,   26,    4,
    5,   32,    0,    0,    6,    7,   26,   28,   40,   32,
   36,    0,   26,   26,   26,   28,   40,   32,   88,   26,
   26,   26,   86,    0,   56,   32,    8,    9,   10,   11,
   55,    0,   13,    0,    0,   56,    0,    0,    0,   26,
   26,    0,   32,   26,   12,   26,   32,   26,   28,   32,
   26,   28,   28,   40,   32,   88,   28,   34,   75,   86,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   75,    0,    0,   75,    0,   75,    0,
    0,    0,    0,    0,    0,    0,   75,    0,    0,    0,
    0,    0,    0,    0,    0,   75,   75,
};
static const short yycheck[] = {                         10,
  125,   10,  125,  125,   10,   10,  123,   67,   10,   40,
   10,   10,   10,   10,   10,   10,  257,   10,   41,   79,
   40,   85,   10,   90,  257,  263,  285,  286,   10,  271,
  272,  125,  267,  259,  293,  125,  305,  100,  267,  262,
  278,  104,  305,  306,  279,  280,  109,  305,  306,  282,
  279,  280,  112,  291,  121,   10,   44,  299,  268,  269,
  270,  125,  300,  301,  305,  274,  275,  276,  277,  281,
   61,  283,  160,  305,  162,  294,  295,  305,   88,   89,
  305,   10,  262,   10,   10,   10,   10,  294,  306,   44,
  305,  305,  123,  264,  305,  123,   10,  305,  295,  273,
  305,  305,  305,  123,  297,  305,  296,  125,   41,  303,
  305,  298,   10,  302,  305,  284,  265,  305,  125,  305,
  305,  305,  305,  305,  305,  257,  305,  305,  298,  305,
  257,  295,   10,   10,  158,  152,   72,  170,  263,  164,
  129,  263,  267,  110,  114,   80,  263,   -1,  117,   -1,
  142,   -1,   -1,  278,  279,  280,  278,   -1,   -1,   -1,
   -1,  278,   -1,   -1,   -1,   -1,  291,   -1,   -1,  291,
  125,   -1,   -1,  267,  291,  300,  301,  267,  300,  301,
  305,   -1,  305,  300,  301,  279,  280,   -1,   -1,  279,
  280,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  266,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  263,   -1,  256,  266,  258,  257,  260,
  261,  257,   -1,   -1,  265,  266,  265,  257,  257,  265,
  265,   -1,  271,  272,  273,  265,  265,  273,  265,  271,
  272,  273,  265,   -1,  305,  273,  287,  288,  289,  290,
  300,   -1,  305,   -1,   -1,  305,   -1,   -1,   -1,  298,
  299,   -1,  298,  302,  305,  297,  302,  299,  298,  297,
  302,  297,  302,  302,  302,  302,  302,  302,  263,  302,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  278,   -1,   -1,  281,   -1,  283,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  291,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  300,  301,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 306
#if YYDEBUG
static const char *yyname[] = {

"end-of-file",0,0,0,0,0,0,0,0,0,"'\\n'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,"'('","')'",0,0,"','",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'='",0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"'d'",
0,0,0,"'h'",0,0,0,0,"'m'",0,0,0,0,0,0,0,0,0,0,0,0,0,"'{'",0,"'}'",0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,"AS","QUEUE","INTERVAL","SIZE","LISTEN","ON","ALL","PORT","EXPIRE",
"MAP","TYPE","HASH","LIST","SINGLE","SSL","SMTPS","CERTIFICATE","DNS","DB",
"PLAIN","EXTERNAL","DOMAIN","CONFIG","SOURCE","RELAY","VIA","DELIVER","TO",
"MAILDIR","MBOX","HOSTNAME","ACCEPT","REJECT","INCLUDE","NETWORK","ERROR","MDA",
"FROM","FOR","ARROW","ENABLE","AUTH","TLS","LOCAL","VIRTUAL","TAG","ALIAS",
"FILTER","STRING","NUMBER",
};
static const char *yyrule[] = {
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
"size : NUMBER",
"size : STRING",
"port : PORT STRING",
"port : PORT NUMBER",
"port :",
"certname : CERTIFICATE STRING",
"certname :",
"ssl : SMTPS",
"ssl : TLS",
"ssl : SSL",
"ssl :",
"auth : ENABLE AUTH",
"auth :",
"tag : TAG STRING",
"tag :",
"expire : EXPIRE STRING",
"expire :",
"credentials : AUTH STRING",
"credentials :",
"main : QUEUE INTERVAL interval",
"main : EXPIRE STRING",
"main : SIZE size",
"main : LISTEN ON STRING port ssl certname auth tag",
"main : HOSTNAME STRING",
"maptype : SINGLE",
"maptype : LIST",
"maptype : HASH",
"mapsource : DNS",
"mapsource : PLAIN STRING",
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
"alias : ALIAS STRING",
"alias :",
"condition : NETWORK mapref",
"condition : DOMAIN mapref alias",
"condition : VIRTUAL STRING",
"condition : LOCAL alias",
"condition : ALL alias",
"condition_list : condition comma condition_list",
"condition_list : condition",
"conditions : condition",
"conditions : '{' condition_list '}'",
"user : AS STRING",
"user :",
"relay_as : AS STRING",
"relay_as :",
"action : DELIVER TO MAILDIR user",
"action : DELIVER TO MAILDIR STRING user",
"action : DELIVER TO MBOX",
"action : DELIVER TO MDA STRING user",
"action : RELAY relay_as",
"action : RELAY VIA STRING port ssl certname credentials relay_as",
"from : FROM mapref",
"from : FROM ALL",
"from : FROM LOCAL",
"from :",
"on : ON STRING",
"on :",
"$$4 :",
"rule : decision on from $$4 FOR conditions action tag expire",

};
#endif
#if YYDEBUG
#include <stdio.h>
#endif

/* define the initial stack-sizes */
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH  YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 500
#define YYMAXDEPTH  500
#endif
#endif

#define YYINITSTACKSIZE 500

int      yydebug;
int      yynerrs;

typedef struct {
    unsigned stacksize;
    short    *s_base;
    short    *s_mark;
    short    *s_last;
    YYSTYPE  *l_base;
    YYSTYPE  *l_mark;
} YYSTACKDATA;

#define YYPURE 0

int      yyerrflag;
int      yychar;
YYSTYPE  yyval;
YYSTYPE  yylval;

/* variables for the parser stack */
static YYSTACKDATA yystack;
#line 1213 "parse.y"

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
		{ "alias",		ALIAS },
		{ "all",		ALL },
		{ "as",			AS },
		{ "auth",		AUTH },
		{ "certificate",	CERTIFICATE },
		{ "config",		CONFIG },
		{ "db",			DB },
		{ "deliver",		DELIVER },
		{ "dns",		DNS },
		{ "domain",		DOMAIN },
		{ "enable",		ENABLE },
		{ "expire",		EXPIRE },
		{ "external",		EXTERNAL },
		{ "filter",		FILTER },
		{ "for",		FOR },
		{ "from",		FROM },
		{ "hash",		HASH },
		{ "hostname",		HOSTNAME },
		{ "include",		INCLUDE },
		{ "interval",		INTERVAL },
		{ "list",		LIST },
		{ "listen",		LISTEN },
		{ "local",		LOCAL },
		{ "maildir",		MAILDIR },
		{ "map",		MAP },
		{ "mbox",		MBOX },
		{ "mda",		MDA },
		{ "network",		NETWORK },
		{ "on",			ON },
		{ "plain",		PLAIN },
		{ "port",		PORT },
		{ "queue",		QUEUE },
		{ "reject",		REJECT },
		{ "relay",		RELAY },
		{ "single",		SINGLE },
		{ "size",		SIZE },
		{ "smtps",		SMTPS },
		{ "source",		SOURCE },
		{ "ssl",		SSL },
		{ "tag",		TAG },
		{ "tls",		TLS },
		{ "to",			TO },
		{ "type",		TYPE },
		{ "via",		VIA },
		{ "virtual",		VIRTUAL },
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

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		log_warn("malloc");
		return (NULL);
	}
	if ((nfile->name = strdup(name)) == NULL) {
		log_warn("malloc");
		free(nfile);
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
	struct map	*m;

	conf = x_conf;
	bzero(conf, sizeof(*conf));

	conf->sc_maxsize = SIZE_MAX;

	conf->sc_maps = calloc(1, sizeof(*conf->sc_maps));
	conf->sc_rules = calloc(1, sizeof(*conf->sc_rules));
	conf->sc_listeners = calloc(1, sizeof(*conf->sc_listeners));
	conf->sc_ssl = calloc(1, sizeof(*conf->sc_ssl));
	conf->sc_filters = calloc(1, sizeof(*conf->sc_filters));
	m = calloc(1, sizeof(*m));

	if (conf->sc_maps == NULL	||
	    conf->sc_rules == NULL	||
	    conf->sc_listeners == NULL	||
	    conf->sc_ssl == NULL	||
	    conf->sc_filters == NULL	||
	    m == NULL) {
		log_warn("cannot allocate memory");
		free(conf->sc_maps);
		free(conf->sc_rules);
		free(conf->sc_listeners);
		free(conf->sc_ssl);
		free(conf->sc_filters);
		free(m);
		return (-1);
	}

	errors = 0;
	last_map_id = 1;

	map = NULL;
	rule = NULL;

	TAILQ_INIT(conf->sc_listeners);
	TAILQ_INIT(conf->sc_maps);
	TAILQ_INIT(conf->sc_rules);
	TAILQ_INIT(conf->sc_filters);
	SPLAY_INIT(conf->sc_ssl);
	SPLAY_INIT(&conf->sc_sessions);

	conf->sc_qexpire = SMTPD_QUEUE_EXPIRY;
	conf->sc_qintval.tv_sec = SMTPD_QUEUE_INTERVAL;
	conf->sc_qintval.tv_usec = 0;
	conf->sc_opts = opts;

	if ((file = pushfile(filename, 0)) == NULL) {
		purge_config(PURGE_EVERYTHING);
		free(m);
		return (-1);
	}
	topfile = file;

	/*
	 * declare special "local" map
	 */
	m->m_id = last_map_id++;
	if (strlcpy(m->m_name, "localhost", sizeof(m->m_name))
	    >= sizeof(m->m_name))
		fatal("strlcpy");
	m->m_type = T_LIST;
	TAILQ_INIT(&m->m_contents);
	TAILQ_INSERT_TAIL(conf->sc_maps, m, m_entry);
	set_localaddrs();

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
		purge_config(PURGE_EVERYTHING);
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
host_dns(const char *s, const char *tag, const char *cert,
    struct listenerlist *al, int max, in_port_t port, u_int8_t flags)
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
		h->ssl_cert_name[0] = '\0';
		if (cert != NULL)
			(void)strlcpy(h->ssl_cert_name, cert, sizeof(h->ssl_cert_name));
		if (tag != NULL)
			(void)strlcpy(h->tag, tag, sizeof(h->tag));

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
host(const char *s, const char *tag, const char *cert, struct listenerlist *al,
    int max, in_port_t port, u_int8_t flags)
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
		h->ssl_cert_name[0] = '\0';
		if (cert != NULL)
			(void)strlcpy(h->ssl_cert_name, cert, sizeof(h->ssl_cert_name));
		if (tag != NULL)
			(void)strlcpy(h->tag, tag, sizeof(h->tag));

		TAILQ_INSERT_HEAD(al, h, entry);
		return (1);
	}

	return (host_dns(s, tag, cert, al, max, port, flags));
}

int
interface(const char *s, const char *tag, const char *cert,
    struct listenerlist *al, int max, in_port_t port, u_int8_t flags)
{
	struct ifaddrs *ifap, *p;
	struct sockaddr_in	*sain;
	struct sockaddr_in6	*sin6;
	struct listener		*h;
	int ret = 0;

	if (getifaddrs(&ifap) == -1)
		fatal("getifaddrs");

	for (p = ifap; p != NULL; p = p->ifa_next) {
		if (strcmp(p->ifa_name, s) != 0 &&
		    ! is_if_in_group(p->ifa_name, s))
			continue;

		if ((h = calloc(1, sizeof(*h))) == NULL)
			fatal(NULL);

		switch (p->ifa_addr->sa_family) {
		case AF_INET:
			sain = (struct sockaddr_in *)&h->ss;
			*sain = *(struct sockaddr_in *)p->ifa_addr;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
			sain->sin_len = sizeof(struct sockaddr_in);
#endif
			sain->sin_port = port;
			break;

		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)&h->ss;
			*sin6 = *(struct sockaddr_in6 *)p->ifa_addr;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN6_LEN
			sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
			sin6->sin6_port = port;
			break;

		default:
			free(h);
			continue;
		}

		h->fd = -1;
		h->port = port;
		h->flags = flags;
		h->ssl = NULL;
		h->ssl_cert_name[0] = '\0';
		if (cert != NULL)
			(void)strlcpy(h->ssl_cert_name, cert, sizeof(h->ssl_cert_name));
		if (tag != NULL)
			(void)strlcpy(h->tag, tag, sizeof(h->tag));

		ret = 1;
		TAILQ_INSERT_HEAD(al, h, entry);
	}

	freeifaddrs(ifap);

	return ret;
}

void
set_localaddrs(void)
{
	struct ifaddrs *ifap, *p;
	struct sockaddr_storage ss;
	struct sockaddr_in	*sain;
	struct sockaddr_in6	*sin6;
	struct map		*m;
	struct mapel		*me;

#ifdef VALGRIND
	bzero(&ss, sizeof(ss));
#endif

	if (getifaddrs(&ifap) == -1)
		fatal("getifaddrs");

	m = map_findbyname("localhost");

	for (p = ifap; p != NULL; p = p->ifa_next) {
		switch (p->ifa_addr->sa_family) {
		case AF_INET:
			sain = (struct sockaddr_in *)&ss;
			*sain = *(struct sockaddr_in *)p->ifa_addr;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
			sain->sin_len = sizeof(struct sockaddr_in);
#endif

			if ((me = calloc(1, sizeof(*me))) == NULL)
				fatal("out of memory");
			me->me_key.med_addr.bits = 32;
			me->me_key.med_addr.ss = *(struct sockaddr_storage *)sain;
			TAILQ_INSERT_TAIL(&m->m_contents, me, me_entry);

			break;

		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)&ss;
			*sin6 = *(struct sockaddr_in6 *)p->ifa_addr;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN6_LEN
			sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif

			if ((me = calloc(1, sizeof(*me))) == NULL)
				fatal("out of memory");
			me->me_key.med_addr.bits = 128;
			me->me_key.med_addr.ss = *(struct sockaddr_storage *)sin6;
			TAILQ_INSERT_TAIL(&m->m_contents, me, me_entry);

			break;
		}
	}

	freeifaddrs(ifap);
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

int
is_if_in_group(const char *ifname, const char *groupname)
{
#ifndef OpenBSD
	return 0;
#else
        unsigned int		 len;
        struct ifgroupreq        ifgr;
        struct ifg_req          *ifg;
	int			 s;
	int			 ret = 0;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		err(1, "socket");

        memset(&ifgr, 0, sizeof(ifgr));
        strlcpy(ifgr.ifgr_name, ifname, IFNAMSIZ);
        if (ioctl(s, SIOCGIFGROUP, (caddr_t)&ifgr) == -1) {
                if (errno == EINVAL || errno == ENOTTY)
			goto end;
		err(1, "SIOCGIFGROUP");
        }

        len = ifgr.ifgr_len;
        ifgr.ifgr_groups =
            (struct ifg_req *)calloc(len/sizeof(struct ifg_req),
		sizeof(struct ifg_req));
        if (ifgr.ifgr_groups == NULL)
                err(1, "getifgroups");
        if (ioctl(s, SIOCGIFGROUP, (caddr_t)&ifgr) == -1)
                err(1, "SIOCGIFGROUP");
	
        ifg = ifgr.ifgr_groups;
        for (; ifg && len >= sizeof(struct ifg_req); ifg++) {
                len -= sizeof(struct ifg_req);
		if (strcmp(ifg->ifgrq_group, groupname) == 0) {
			ret = 1;
			break;
		}
        }
        free(ifgr.ifgr_groups);

end:
	close(s);
	return ret;
#endif
}
#line 1482 "parse.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(YYSTACKDATA *data)
{
    int i;
    unsigned newsize;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = data->stacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;

    i = data->s_mark - data->s_base;
    newss = (data->s_base != 0)
          ? (short *)realloc(data->s_base, newsize * sizeof(*newss))
          : (short *)malloc(newsize * sizeof(*newss));
    if (newss == 0)
        return -1;

    data->s_base  = newss;
    data->s_mark = newss + i;

    newvs = (data->l_base != 0)
          ? (YYSTYPE *)realloc(data->l_base, newsize * sizeof(*newvs))
          : (YYSTYPE *)malloc(newsize * sizeof(*newvs));
    if (newvs == 0)
        return -1;

    data->l_base = newvs;
    data->l_mark = newvs + i;

    data->stacksize = newsize;
    data->s_last = data->s_base + newsize - 1;
    return 0;
}

#if YYPURE || defined(YY_NO_LEAKS)
static void yyfreestack(YYSTACKDATA *data)
{
    free(data->s_base);
    free(data->l_base);
    memset(data, 0, sizeof(*data));
}
#else
#define yyfreestack(data) /* nothing */
#endif

#define YYABORT  goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR  goto yyerrlab

int
YYPARSE_DECL()
{
    int yym, yyn, yystate;
#if YYDEBUG
    const char *yys;

    if ((yys = getenv("YYDEBUG")) != 0)
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = YYEMPTY;
    yystate = 0;

#if YYPURE
    memset(&yystack, 0, sizeof(yystack));
#endif

    if (yystack.s_base == NULL && yygrowstack(&yystack)) goto yyoverflow;
    yystack.s_mark = yystack.s_base;
    yystack.l_mark = yystack.l_base;
    yystate = 0;
    *yystack.s_mark = 0;

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
        if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
        {
            goto yyoverflow;
        }
        yystate = yytable[yyn];
        *++yystack.s_mark = yytable[yyn];
        *++yystack.l_mark = yylval;
        yychar = YYEMPTY;
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

    yyerror("syntax error");

    goto yyerrlab;

yyerrlab:
    ++yynerrs;

yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yystack.s_mark]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yystack.s_mark, yytable[yyn]);
#endif
                if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
                {
                    goto yyoverflow;
                }
                yystate = yytable[yyn];
                *++yystack.s_mark = yytable[yyn];
                *++yystack.l_mark = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yystack.s_mark);
#endif
                if (yystack.s_mark <= yystack.s_base) goto yyabort;
                --yystack.s_mark;
                --yystack.l_mark;
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
        yychar = YYEMPTY;
        goto yyloop;
    }

yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym)
        yyval = yystack.l_mark[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 8:
#line 154 "parse.y"
	{ file->errors++; }
break;
case 9:
#line 157 "parse.y"
	{
			struct file	*nfile;

			if ((nfile = pushfile(yystack.l_mark[0].v.string, 0)) == NULL) {
				yyerror("failed to include file %s", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);

			file = nfile;
			lungetc('\n');
		}
break;
case 10:
#line 172 "parse.y"
	{
			if (symset(yystack.l_mark[-2].v.string, yystack.l_mark[0].v.string, 0) == -1)
				fatal("cannot store variable");
			free(yystack.l_mark[-2].v.string);
			free(yystack.l_mark[0].v.string);
		}
break;
case 17:
#line 192 "parse.y"
	{ yyval.v.number = 1; }
break;
case 18:
#line 193 "parse.y"
	{ yyval.v.number = 60; }
break;
case 19:
#line 194 "parse.y"
	{ yyval.v.number = 3600; }
break;
case 20:
#line 195 "parse.y"
	{ yyval.v.number = 86400; }
break;
case 21:
#line 198 "parse.y"
	{
			if (yystack.l_mark[-1].v.number < 0) {
				yyerror("invalid interval: %lld", yystack.l_mark[-1].v.number);
				YYERROR;
			}
			yyval.v.tv.tv_usec = 0;
			yyval.v.tv.tv_sec = yystack.l_mark[-1].v.number * yystack.l_mark[0].v.number;
		}
break;
case 22:
#line 208 "parse.y"
	{
			if (yystack.l_mark[0].v.number < 0) {
				yyerror("invalid size: %lld", yystack.l_mark[0].v.number);
				YYERROR;
			}
			yyval.v.number = yystack.l_mark[0].v.number;
		}
break;
case 23:
#line 215 "parse.y"
	{
			long long result;

			if (scan_scaled(yystack.l_mark[0].v.string, &result) == -1 || result < 0) {
				yyerror("invalid size: %s", yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);

			yyval.v.number = result;
		}
break;
case 24:
#line 228 "parse.y"
	{
			struct servent	*servent;

			servent = getservbyname(yystack.l_mark[0].v.string, "tcp");
			if (servent == NULL) {
				yyerror("port %s is invalid", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			yyval.v.number = servent->s_port;
			free(yystack.l_mark[0].v.string);
		}
break;
case 25:
#line 240 "parse.y"
	{
			if (yystack.l_mark[0].v.number <= 0 || yystack.l_mark[0].v.number >= (int)USHRT_MAX) {
				yyerror("invalid port: %lld", yystack.l_mark[0].v.number);
				YYERROR;
			}
			yyval.v.number = htons(yystack.l_mark[0].v.number);
		}
break;
case 26:
#line 247 "parse.y"
	{
			yyval.v.number = 0;
		}
break;
case 27:
#line 252 "parse.y"
	{
			if ((yyval.v.string = strdup(yystack.l_mark[0].v.string)) == NULL)
				fatal(NULL);
			free(yystack.l_mark[0].v.string);
		}
break;
case 28:
#line 257 "parse.y"
	{ yyval.v.string = NULL; }
break;
case 29:
#line 260 "parse.y"
	{ yyval.v.number = F_SMTPS; }
break;
case 30:
#line 261 "parse.y"
	{ yyval.v.number = F_STARTTLS; }
break;
case 31:
#line 262 "parse.y"
	{ yyval.v.number = F_SSL; }
break;
case 32:
#line 263 "parse.y"
	{ yyval.v.number = 0; }
break;
case 33:
#line 266 "parse.y"
	{ yyval.v.number = 1; }
break;
case 34:
#line 267 "parse.y"
	{ yyval.v.number = 0; }
break;
case 35:
#line 270 "parse.y"
	{
       			if (strlen(yystack.l_mark[0].v.string) >= MAX_TAG_SIZE) {
       				yyerror("tag name too long");
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}

			yyval.v.string = yystack.l_mark[0].v.string;
		}
break;
case 36:
#line 279 "parse.y"
	{ yyval.v.string = NULL; }
break;
case 37:
#line 282 "parse.y"
	{
			yyval.v.number = delaytonum(yystack.l_mark[0].v.string);
			if (yyval.v.number == -1) {
				yyerror("invalid expire delay: %s", yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 38:
#line 290 "parse.y"
	{ yyval.v.number = conf->sc_qexpire; }
break;
case 39:
#line 293 "parse.y"
	{
			struct map *m;

			if ((m = map_findbyname(yystack.l_mark[0].v.string)) == NULL) {
				yyerror("no such map: %s", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
			yyval.v.number = m->m_id;
		}
break;
case 40:
#line 304 "parse.y"
	{ yyval.v.number = 0; }
break;
case 41:
#line 307 "parse.y"
	{
			conf->sc_qintval = yystack.l_mark[0].v.tv;
		}
break;
case 42:
#line 310 "parse.y"
	{
			conf->sc_qexpire = delaytonum(yystack.l_mark[0].v.string);
			if (conf->sc_qexpire == -1) {
				yyerror("invalid expire delay: %s", yystack.l_mark[0].v.string);
				YYERROR;
			}
		}
break;
case 43:
#line 317 "parse.y"
	{
       			conf->sc_maxsize = yystack.l_mark[0].v.number;
		}
break;
case 44:
#line 320 "parse.y"
	{
			char		*cert;
			char		*tag;
			u_int8_t	 flags;

			if (yystack.l_mark[-3].v.number == F_SSL) {
				yyerror("syntax error");
				free(yystack.l_mark[0].v.string);
				free(yystack.l_mark[-2].v.string);
				free(yystack.l_mark[-5].v.string);
				YYERROR;
			}

			if (yystack.l_mark[-3].v.number == 0 && (yystack.l_mark[-2].v.string != NULL || yystack.l_mark[-1].v.number)) {
				yyerror("error: must specify tls or smtps");
				free(yystack.l_mark[0].v.string);
				free(yystack.l_mark[-2].v.string);
				free(yystack.l_mark[-5].v.string);
				YYERROR;
			}

			if (yystack.l_mark[-4].v.number == 0) {
				if (yystack.l_mark[-3].v.number == F_SMTPS)
					yystack.l_mark[-4].v.number = htons(465);
				else
					yystack.l_mark[-4].v.number = htons(25);
			}

			cert = (yystack.l_mark[-2].v.string != NULL) ? yystack.l_mark[-2].v.string : yystack.l_mark[-5].v.string;
			flags = yystack.l_mark[-3].v.number;

			if (yystack.l_mark[-1].v.number)
				flags |= F_AUTH;

			if (yystack.l_mark[-3].v.number && ssl_load_certfile(cert, F_SCERT) < 0) {
				yyerror("cannot load certificate: %s", cert);
				free(yystack.l_mark[0].v.string);
				free(yystack.l_mark[-2].v.string);
				free(yystack.l_mark[-5].v.string);
				YYERROR;
			}

			tag = yystack.l_mark[-5].v.string;
			if (yystack.l_mark[0].v.string != NULL)
				tag = yystack.l_mark[0].v.string;

			if (! interface(yystack.l_mark[-5].v.string, tag, cert, conf->sc_listeners,
				MAX_LISTEN, yystack.l_mark[-4].v.number, flags)) {
				if (host(yystack.l_mark[-5].v.string, tag, cert, conf->sc_listeners,
					MAX_LISTEN, yystack.l_mark[-4].v.number, flags) <= 0) {
					yyerror("invalid virtual ip or interface: %s", yystack.l_mark[-5].v.string);
					free(yystack.l_mark[0].v.string);
					free(yystack.l_mark[-2].v.string);
					free(yystack.l_mark[-5].v.string);
					YYERROR;
				}
			}
			free(yystack.l_mark[0].v.string);
			free(yystack.l_mark[-2].v.string);
			free(yystack.l_mark[-5].v.string);
		}
break;
case 45:
#line 381 "parse.y"
	{
			if (strlcpy(conf->sc_hostname, yystack.l_mark[0].v.string,
			    sizeof(conf->sc_hostname)) >=
			    sizeof(conf->sc_hostname)) {
				yyerror("hostname truncated");
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
		}
break;
case 46:
#line 425 "parse.y"
	{ map->m_type = T_SINGLE; }
break;
case 47:
#line 426 "parse.y"
	{ map->m_type = T_LIST; }
break;
case 48:
#line 427 "parse.y"
	{ map->m_type = T_HASH; }
break;
case 49:
#line 430 "parse.y"
	{ map->m_src = S_DNS; }
break;
case 50:
#line 431 "parse.y"
	{
			map->m_src = S_PLAIN;
			if (strlcpy(map->m_config, yystack.l_mark[0].v.string, sizeof(map->m_config))
			    >= sizeof(map->m_config))
				err(1, "pathname too long");
		}
break;
case 51:
#line 437 "parse.y"
	{
			map->m_src = S_DB;
			if (strlcpy(map->m_config, yystack.l_mark[0].v.string, sizeof(map->m_config))
			    >= sizeof(map->m_config))
				err(1, "pathname too long");
		}
break;
case 52:
#line 443 "parse.y"
	{ map->m_src = S_EXT; }
break;
case 55:
#line 448 "parse.y"
	{
		}
break;
case 58:
#line 456 "parse.y"
	{
			struct map	*m;

			TAILQ_FOREACH(m, conf->sc_maps, m_entry)
				if (strcmp(m->m_name, yystack.l_mark[0].v.string) == 0)
					break;

			if (m != NULL) {
				yyerror("map %s defined twice", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			if ((m = calloc(1, sizeof(*m))) == NULL)
				fatal("out of memory");
			if (strlcpy(m->m_name, yystack.l_mark[0].v.string, sizeof(m->m_name)) >=
			    sizeof(m->m_name)) {
				yyerror("map name truncated");
				free(m);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}

			m->m_id = last_map_id++;
			m->m_type = T_SINGLE;

			if (m->m_id == INT_MAX) {
				yyerror("too many maps defined");
				free(yystack.l_mark[0].v.string);
				free(m);
				YYERROR;
			}
			map = m;
		}
break;
case 59:
#line 488 "parse.y"
	{
			if (map->m_src == S_NONE) {
				yyerror("map %s has no source defined", yystack.l_mark[-5].v.string);
				free(map);
				map = NULL;
				YYERROR;
			}
			TAILQ_INSERT_TAIL(conf->sc_maps, map, m_entry);
			map = NULL;
		}
break;
case 60:
#line 500 "parse.y"
	{
			struct mapel	*me;

			if ((me = calloc(1, sizeof(*me))) == NULL)
				fatal("out of memory");

			if (strlcpy(me->me_key.med_string, yystack.l_mark[-2].v.string,
			    sizeof(me->me_key.med_string)) >=
			    sizeof(me->me_key.med_string) ||
			    strlcpy(me->me_val.med_string, yystack.l_mark[0].v.string,
			    sizeof(me->me_val.med_string)) >=
			    sizeof(me->me_val.med_string)) {
				yyerror("map elements too long: %s, %s",
				    yystack.l_mark[-2].v.string, yystack.l_mark[0].v.string);
				free(me);
				free(yystack.l_mark[-2].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[-2].v.string);
			free(yystack.l_mark[0].v.string);

			TAILQ_INSERT_TAIL(contents, me, me_entry);
		}
break;
case 63:
#line 530 "parse.y"
	{
			struct mapel	*me;
			int bits;
			struct sockaddr_in ssin;
			struct sockaddr_in6 ssin6;

			if ((me = calloc(1, sizeof(*me))) == NULL)
				fatal("out of memory");

			/* Attempt detection of $1 format */
			if (strchr(yystack.l_mark[0].v.string, '/') != NULL) {
				/* Dealing with a netmask */
				bzero(&ssin, sizeof(struct sockaddr_in));
				bits = inet_net_pton(AF_INET, yystack.l_mark[0].v.string, &ssin.sin_addr, sizeof(struct in_addr));
				if (bits != -1) {
					ssin.sin_family = AF_INET;
					me->me_key.med_addr.bits = bits;
					memcpy(&me->me_key.med_addr.ss, &ssin, sizeof(ssin));
#ifdef HAVE_STRUCT_SOCKADDR_SS_LEN
					me->me_key.med_addr.ss.ss_len = sizeof(struct sockaddr_in);
#endif
				}
				else {
					bzero(&ssin6, sizeof(struct sockaddr_in6));
					bits = inet_net_pton(AF_INET6, yystack.l_mark[0].v.string, &ssin6.sin6_addr, sizeof(struct in6_addr));
					if (bits == -1)
						err(1, "inet_net_pton");
					ssin6.sin6_family = AF_INET6;
					me->me_key.med_addr.bits = bits;
					memcpy(&me->me_key.med_addr.ss, &ssin6, sizeof(ssin6));
#ifdef HAVE_STRUCT_SOCKADDR_SS_LEN
					me->me_key.med_addr.ss.ss_len = sizeof(struct sockaddr_in6);
#endif
				}
			}
			else {
				/* IP address ? */
				if (inet_pton(AF_INET, yystack.l_mark[0].v.string, &ssin.sin_addr) == 1) {
					ssin.sin_family = AF_INET;
					me->me_key.med_addr.bits = 32;
					memcpy(&me->me_key.med_addr.ss, &ssin, sizeof(ssin));
#ifdef HAVE_STRUCT_SOCKADDR_SS_LEN
					me->me_key.med_addr.ss.ss_len = sizeof(struct sockaddr_in);
#endif
				}
				else if (inet_pton(AF_INET6, yystack.l_mark[0].v.string, &ssin6.sin6_addr) == 1) {
					ssin6.sin6_family = AF_INET6;
					me->me_key.med_addr.bits = 128;
					memcpy(&me->me_key.med_addr.ss, &ssin6, sizeof(ssin6));
#ifdef HAVE_STRUCT_SOCKADDR_SS_LEN
					me->me_key.med_addr.ss.ss_len = sizeof(struct sockaddr_in6);
#endif
				}
				else {
					/* either a hostname or a value unrelated to network */
					if (strlcpy(me->me_key.med_string, yystack.l_mark[0].v.string,
						sizeof(me->me_key.med_string)) >=
					    sizeof(me->me_key.med_string)) {
						yyerror("map element too long: %s", yystack.l_mark[0].v.string);
						free(me);
						free(yystack.l_mark[0].v.string);
						YYERROR;
					}
				}
			}
			free(yystack.l_mark[0].v.string);
			TAILQ_INSERT_TAIL(contents, me, me_entry);
		}
break;
case 66:
#line 604 "parse.y"
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
			m->m_src = S_NONE;

			TAILQ_INIT(&m->m_contents);

			if ((me = calloc(1, sizeof(*me))) == NULL)
				fatal("out of memory");

			/* Attempt detection of $1 format */
			if (strchr(yystack.l_mark[0].v.string, '/') != NULL) {
				/* Dealing with a netmask */
				bzero(&ssin, sizeof(struct sockaddr_in));
				bits = inet_net_pton(AF_INET, yystack.l_mark[0].v.string, &ssin.sin_addr, sizeof(struct in_addr));
				if (bits != -1) {
					ssin.sin_family = AF_INET;
					me->me_key.med_addr.bits = bits;
					memcpy(&me->me_key.med_addr.ss, &ssin, sizeof(ssin));
#ifdef HAVE_STRUCT_SOCKADDR_SS_LEN
					me->me_key.med_addr.ss.ss_len = sizeof(struct sockaddr_in);
#endif
				}
				else {
					bzero(&ssin6, sizeof(struct sockaddr_in6));
					bits = inet_net_pton(AF_INET6, yystack.l_mark[0].v.string, &ssin6.sin6_addr, sizeof(struct in6_addr));
					if (bits == -1)
						err(1, "inet_net_pton");
					ssin6.sin6_family = AF_INET6;
					me->me_key.med_addr.bits = bits;
					memcpy(&me->me_key.med_addr.ss, &ssin6, sizeof(ssin6));
#ifdef HAVE_STRUCT_SOCKADDR_SS_LEN
					me->me_key.med_addr.ss.ss_len = sizeof(struct sockaddr_in6);
#endif
				}
			}
			else {
				/* IP address ? */
				if (inet_pton(AF_INET, yystack.l_mark[0].v.string, &ssin.sin_addr) == 1) {
					ssin.sin_family = AF_INET;
					me->me_key.med_addr.bits = 32;
					memcpy(&me->me_key.med_addr.ss, &ssin, sizeof(ssin));
#ifdef HAVE_STRUCT_SOCKADDR_SS_LEN
					me->me_key.med_addr.ss.ss_len = sizeof(struct sockaddr_in);
#endif
				}
				else if (inet_pton(AF_INET6, yystack.l_mark[0].v.string, &ssin6.sin6_addr) == 1) {
					ssin6.sin6_family = AF_INET6;
					me->me_key.med_addr.bits = 128;
					memcpy(&me->me_key.med_addr.ss, &ssin6, sizeof(ssin6));
#ifdef HAVE_STRUCT_SOCKADDR_SS_LEN
					me->me_key.med_addr.ss.ss_len = sizeof(struct sockaddr_in6);
#endif
				}
				else {
					/* either a hostname or a value unrelated to network */
					if (strlcpy(me->me_key.med_string, yystack.l_mark[0].v.string,
						sizeof(me->me_key.med_string)) >=
					    sizeof(me->me_key.med_string)) {
						yyerror("map element too long: %s", yystack.l_mark[0].v.string);
						free(me);
						free(m);
						free(yystack.l_mark[0].v.string);
						YYERROR;
					}
				}
			}
			free(yystack.l_mark[0].v.string);

			TAILQ_INSERT_TAIL(&m->m_contents, me, me_entry);
			TAILQ_INSERT_TAIL(conf->sc_maps, m, m_entry);
			yyval.v.object = m->m_id;
		}
break;
case 67:
#line 694 "parse.y"
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
case 68:
#line 716 "parse.y"
	{
			TAILQ_INSERT_TAIL(conf->sc_maps, map, m_entry);
			yyval.v.object = map->m_id;
		}
break;
case 69:
#line 720 "parse.y"
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
case 70:
#line 742 "parse.y"
	{
			TAILQ_INSERT_TAIL(conf->sc_maps, map, m_entry);
			yyval.v.object = map->m_id;
		}
break;
case 71:
#line 746 "parse.y"
	{
			struct map	*m;

			if ((m = map_findbyname(yystack.l_mark[0].v.string)) == NULL) {
				yyerror("no such map: %s", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
			m->m_flags |= F_USED;
			yyval.v.object = m->m_id;
		}
break;
case 72:
#line 760 "parse.y"
	{ yyval.v.number = 1; }
break;
case 73:
#line 761 "parse.y"
	{ yyval.v.number = 0; }
break;
case 74:
#line 764 "parse.y"
	{ yyval.v.string = yystack.l_mark[0].v.string; }
break;
case 75:
#line 765 "parse.y"
	{ yyval.v.string = NULL; }
break;
case 76:
#line 768 "parse.y"
	{
			struct cond	*c;

			if ((c = calloc(1, sizeof *c)) == NULL)
				fatal("out of memory");
			c->c_type = C_NET;
			c->c_map = yystack.l_mark[0].v.object;
			yyval.v.cond = c;
		}
break;
case 77:
#line 777 "parse.y"
	{
			struct cond	*c;
			struct map	*m;

			if (yystack.l_mark[0].v.string) {
				if ((m = map_findbyname(yystack.l_mark[0].v.string)) == NULL) {
					yyerror("no such map: %s", yystack.l_mark[0].v.string);
					free(yystack.l_mark[0].v.string);
					YYERROR;
				}
				rule->r_amap = m->m_id;
			}

			if ((c = calloc(1, sizeof *c)) == NULL)
				fatal("out of memory");
			c->c_type = C_DOM;
			c->c_map = yystack.l_mark[-1].v.object;
			yyval.v.cond = c;
		}
break;
case 78:
#line 796 "parse.y"
	{
			struct cond	*c;
			struct map	*m;

			if ((m = map_findbyname(yystack.l_mark[0].v.string)) == NULL) {
				yyerror("no such map: %s", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			free(yystack.l_mark[0].v.string);
			m->m_flags |= F_USED;

			if ((c = calloc(1, sizeof *c)) == NULL)
				fatal("out of memory");
			c->c_type = C_VDOM;
			c->c_map = m->m_id;
			yyval.v.cond = c;
		}
break;
case 79:
#line 814 "parse.y"
	{
			struct cond	*c;
			struct map	*m;
			struct mapel	*me;

			if (yystack.l_mark[0].v.string) {
				if ((m = map_findbyname(yystack.l_mark[0].v.string)) == NULL) {
					yyerror("no such map: %s", yystack.l_mark[0].v.string);
					free(yystack.l_mark[0].v.string);
					YYERROR;
				}
				rule->r_amap = m->m_id;
			}

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

			(void)strlcpy(me->me_key.med_string, "localhost",
			    sizeof(me->me_key.med_string));
			TAILQ_INSERT_TAIL(&m->m_contents, me, me_entry);

			if ((me = calloc(1, sizeof(*me))) == NULL)
				fatal("out of memory");

			if (gethostname(me->me_key.med_string,
				sizeof(me->me_key.med_string)) == -1) {
				yyerror("gethostname() failed");
				free(me);
				free(m);
				YYERROR;
			}
			TAILQ_INSERT_TAIL(&m->m_contents, me, me_entry);

			TAILQ_INSERT_TAIL(conf->sc_maps, m, m_entry);

			if ((c = calloc(1, sizeof *c)) == NULL)
				fatal("out of memory");
			c->c_type = C_DOM;
			c->c_map = m->m_id;

			yyval.v.cond = c;
		}
break;
case 80:
#line 872 "parse.y"
	{
			struct cond	*c;
			struct map	*m;

			if ((c = calloc(1, sizeof *c)) == NULL)
				fatal("out of memory");
			c->c_type = C_ALL;

			if (yystack.l_mark[0].v.string) {
				if ((m = map_findbyname(yystack.l_mark[0].v.string)) == NULL) {
					yyerror("no such map: %s", yystack.l_mark[0].v.string);
					free(yystack.l_mark[0].v.string);
					YYERROR;
				}
				rule->r_amap = m->m_id;
			}
			yyval.v.cond = c;
		}
break;
case 81:
#line 892 "parse.y"
	{
			TAILQ_INSERT_TAIL(conditions, yystack.l_mark[-2].v.cond, c_entry);
		}
break;
case 82:
#line 895 "parse.y"
	{
			TAILQ_INSERT_TAIL(conditions, yystack.l_mark[0].v.cond, c_entry);
		}
break;
case 83:
#line 900 "parse.y"
	{
			TAILQ_INSERT_TAIL(conditions, yystack.l_mark[0].v.cond, c_entry);
		}
break;
case 85:
#line 906 "parse.y"
	{
			struct passwd *pw;

			pw = getpwnam(yystack.l_mark[0].v.string);
			if (pw == NULL) {
				yyerror("user '%s' does not exist.", yystack.l_mark[0].v.string);
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}
			yyval.v.string = yystack.l_mark[0].v.string;
		}
break;
case 86:
#line 917 "parse.y"
	{ yyval.v.string = NULL; }
break;
case 87:
#line 920 "parse.y"
	{
			struct mailaddr maddr, *maddrp;
			char *p;

			bzero(&maddr, sizeof (maddr));

			p = strrchr(yystack.l_mark[0].v.string, '@');
			if (p == NULL) {
				if (strlcpy(maddr.user, yystack.l_mark[0].v.string, sizeof (maddr.user))
				    >= sizeof (maddr.user))
					yyerror("user-part too long");
					free(yystack.l_mark[0].v.string);
					YYERROR;
			}
			else {
				if (p == yystack.l_mark[0].v.string) {
					/* domain only */
					p++;
					if (strlcpy(maddr.domain, p, sizeof (maddr.domain))
					    >= sizeof (maddr.domain)) {
						yyerror("user-part too long");
						free(yystack.l_mark[0].v.string);
						YYERROR;
					}
				}
				else {
					*p++ = '\0';
					if (strlcpy(maddr.user, yystack.l_mark[0].v.string, sizeof (maddr.user))
					    >= sizeof (maddr.user)) {
						yyerror("user-part too long");
						free(yystack.l_mark[0].v.string);
						YYERROR;
					}
					if (strlcpy(maddr.domain, p, sizeof (maddr.domain))
					    >= sizeof (maddr.domain)) {
						yyerror("domain-part too long");
						free(yystack.l_mark[0].v.string);
						YYERROR;
					}
				}
			}

			if (maddr.user[0] == '\0' && maddr.domain[0] == '\0') {
				yyerror("invalid 'relay as' value");
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}

			if (maddr.domain[0] == '\0') {
				if (strlcpy(maddr.domain, conf->sc_hostname,
					sizeof (maddr.domain))
				    >= sizeof (maddr.domain)) {
					fatalx("domain too long");
					yyerror("domain-part too long");
					free(yystack.l_mark[0].v.string);
					YYERROR;
				}
			}
			
			maddrp = calloc(1, sizeof (*maddrp));
			if (maddrp == NULL)
				fatal("calloc");
			*maddrp = maddr;
			free(yystack.l_mark[0].v.string);

			yyval.v.maddr = maddrp;
		}
break;
case 88:
#line 987 "parse.y"
	{ yyval.v.maddr = NULL; }
break;
case 89:
#line 990 "parse.y"
	{
			rule->r_user = yystack.l_mark[0].v.string;
			rule->r_action = A_MAILDIR;
			if (strlcpy(rule->r_value.buffer, "~/Maildir",
			    sizeof(rule->r_value.buffer)) >=
			    sizeof(rule->r_value.buffer))
				fatal("pathname too long");
		}
break;
case 90:
#line 998 "parse.y"
	{
			rule->r_user = yystack.l_mark[0].v.string;
			rule->r_action = A_MAILDIR;
			if (strlcpy(rule->r_value.buffer, yystack.l_mark[-1].v.string,
			    sizeof(rule->r_value.buffer)) >=
			    sizeof(rule->r_value.buffer))
				fatal("pathname too long");
			free(yystack.l_mark[-1].v.string);
		}
break;
case 91:
#line 1007 "parse.y"
	{
			rule->r_action = A_MBOX;
			if (strlcpy(rule->r_value.buffer, _PATH_MAILDIR "/%u",
			    sizeof(rule->r_value.buffer))
			    >= sizeof(rule->r_value.buffer))
				fatal("pathname too long");
		}
break;
case 92:
#line 1014 "parse.y"
	{
			rule->r_user = yystack.l_mark[0].v.string;
			rule->r_action = A_EXT;
			if (strlcpy(rule->r_value.buffer, yystack.l_mark[-1].v.string,
			    sizeof(rule->r_value.buffer))
			    >= sizeof(rule->r_value.buffer))
				fatal("command too long");
			free(yystack.l_mark[-1].v.string);
		}
break;
case 93:
#line 1023 "parse.y"
	{
			rule->r_action = A_RELAY;
			rule->r_as = yystack.l_mark[0].v.maddr;
		}
break;
case 94:
#line 1027 "parse.y"
	{
			rule->r_action = A_RELAYVIA;
			rule->r_as = yystack.l_mark[0].v.maddr;

			if (yystack.l_mark[-3].v.number == 0 && (yystack.l_mark[-2].v.string != NULL || yystack.l_mark[-1].v.number)) {
				yyerror("error: must specify tls, smtps, or ssl");
				free(yystack.l_mark[-2].v.string);
				free(yystack.l_mark[-5].v.string);
				YYERROR;
			}

			if (strlcpy(rule->r_value.relayhost.hostname, yystack.l_mark[-5].v.string,
			    sizeof(rule->r_value.relayhost.hostname))
			    >= sizeof(rule->r_value.relayhost.hostname))
				fatal("hostname too long");

			rule->r_value.relayhost.port = yystack.l_mark[-4].v.number;
			rule->r_value.relayhost.flags |= yystack.l_mark[-3].v.number;

			if (yystack.l_mark[-1].v.number) {
				rule->r_value.relayhost.flags |= F_AUTH;
				rule->r_value.relayhost.secmapid = yystack.l_mark[-1].v.number;
			}

			if (yystack.l_mark[-2].v.string != NULL) {
				if (ssl_load_certfile(yystack.l_mark[-2].v.string, F_CCERT) < 0) {
					yyerror("cannot load certificate: %s",
					    yystack.l_mark[-2].v.string);
					free(yystack.l_mark[-2].v.string);
					free(yystack.l_mark[-5].v.string);
					YYERROR;
				}
				if (strlcpy(rule->r_value.relayhost.cert, yystack.l_mark[-2].v.string,
					sizeof(rule->r_value.relayhost.cert))
				    >= sizeof(rule->r_value.relayhost.cert))
					fatal("certificate path too long");
			}

			free(yystack.l_mark[-5].v.string);
			free(yystack.l_mark[-2].v.string);
		}
break;
case 95:
#line 1070 "parse.y"
	{
			yyval.v.number = yystack.l_mark[0].v.object;
		}
break;
case 96:
#line 1073 "parse.y"
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
#ifdef HAVE_STRUCT_SOCKADDR_SS_LEN
			me->me_key.med_addr.ss.ss_len = sizeof(struct sockaddr_in);
#endif
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
			me->me_key.med_addr.bits = 0;
#ifdef HAVE_STRUCT_SOCKADDR_SS_LEN
			me->me_key.med_addr.ss.ss_len = sizeof(struct sockaddr_in6);
#endif
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
case 97:
#line 1128 "parse.y"
	{
			struct map	*m;

			m = map_findbyname("localhost");
			yyval.v.number = m->m_id;
		}
break;
case 98:
#line 1134 "parse.y"
	{
			struct map	*m;

			m = map_findbyname("localhost");
			yyval.v.number = m->m_id;
		}
break;
case 99:
#line 1142 "parse.y"
	{
       			if (strlen(yystack.l_mark[0].v.string) >= MAX_TAG_SIZE) {
       				yyerror("interface, address or tag name too long");
				free(yystack.l_mark[0].v.string);
				YYERROR;
			}

			yyval.v.string = yystack.l_mark[0].v.string;
		}
break;
case 100:
#line 1151 "parse.y"
	{ yyval.v.string = NULL; }
break;
case 101:
#line 1154 "parse.y"
	{

			if ((rule = calloc(1, sizeof(*rule))) == NULL)
				fatal("out of memory");
			rule->r_sources = map_find(yystack.l_mark[0].v.number);


			if ((conditions = calloc(1, sizeof(*conditions))) == NULL)
				fatal("out of memory");

			if (yystack.l_mark[-1].v.string)
				(void)strlcpy(rule->r_tag, yystack.l_mark[-1].v.string, sizeof(rule->r_tag));
			free(yystack.l_mark[-1].v.string);


			TAILQ_INIT(conditions);

		}
break;
case 102:
#line 1171 "parse.y"
	{
			struct rule	*subr;
			struct cond	*cond;

			if (yystack.l_mark[-1].v.string)
				(void)strlcpy(rule->r_tag, yystack.l_mark[-1].v.string, sizeof(rule->r_tag));
			free(yystack.l_mark[-1].v.string);

			rule->r_qexpire = yystack.l_mark[0].v.number;

			while ((cond = TAILQ_FIRST(conditions)) != NULL) {

				if ((subr = calloc(1, sizeof(*subr))) == NULL)
					fatal("out of memory");

				*subr = *rule;

				subr->r_condition = *cond;
				
				TAILQ_REMOVE(conditions, cond, c_entry);
				TAILQ_INSERT_TAIL(conf->sc_rules, subr, r_entry);

				free(cond);
			}

			if (rule->r_amap) {
				if (rule->r_action == A_RELAY ||
				    rule->r_action == A_RELAYVIA) {
					yyerror("aliases set on a relay rule");
					free(conditions);
					free(rule);
					YYERROR;
				}
			}

			free(conditions);
			free(rule);
			conditions = NULL;
			rule = NULL;
		}
break;
#line 2864 "parse.c"
    }
    yystack.s_mark -= yym;
    yystate = *yystack.s_mark;
    yystack.l_mark -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yystack.s_mark = YYFINAL;
        *++yystack.l_mark = yyval;
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
to state %d\n", YYPREFIX, *yystack.s_mark, yystate);
#endif
    if (yystack.s_mark >= yystack.s_last && yygrowstack(&yystack))
    {
        goto yyoverflow;
    }
    *++yystack.s_mark = (short) yystate;
    *++yystack.l_mark = yyval;
    goto yyloop;

yyoverflow:
    yyerror("yacc stack overflow");

yyabort:
    yyfreestack(&yystack);
    return (1);

yyaccept:
    yyfreestack(&yystack);
    return (0);
}
