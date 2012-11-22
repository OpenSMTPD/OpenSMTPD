/*	$OpenBSD: smtpd.h,v 1.395 2012/11/12 14:58:53 eric Exp $	*/

/*
 * Copyright (c) 2008 Gilles Chehade <gilles@openbsd.org>
 * Copyright (c) 2008 Pierre-Yves Ritschard <pyr@openbsd.org>
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

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

#include "filter_api.h"
#include "ioev.h"
#include "iobuf.h"

#define CONF_FILE		 "/etc/mail/smtpd.conf"
#define MAX_LISTEN		 16
#define PROC_COUNT		 9
#define MAX_NAME_SIZE		 64

#define MAX_HOPS_COUNT		 100
#define	DEFAULT_MAX_BODY_SIZE	(35*1024*1024)

#define MAX_TAG_SIZE		 32

#define	MAX_TABLE_BACKEND_SIZE	 32

/* return and forward path size */
#define	MAX_FILTER_NAME		 32
#define MAX_PATH_SIZE		 256
/*#define MAX_RULEBUFFER_LEN	 512*/
#define	EXPAND_BUFFER		 1024

#define SMTPD_QUEUE_INTERVAL	 (15 * 60)
#define SMTPD_QUEUE_MAXINTERVAL	 (4 * 60 * 60)
#define SMTPD_QUEUE_EXPIRY	 (4 * 24 * 60 * 60)
#define SMTPD_USER		 "_smtpd"
#define SMTPD_FILTER_USER	 "_smtpmfa"
#define SMTPD_SOCKET		 "/var/run/smtpd.sock"
#define SMTPD_BANNER		 "220 %s ESMTP OpenSMTPD"
#define SMTPD_SESSION_TIMEOUT	 300
#define SMTPD_BACKLOG		 5

#define	PATH_SMTPCTL		"/usr/sbin/smtpctl"

#define PATH_SPOOL		"/var/spool/smtpd"
#define PATH_OFFLINE		"/offline"
#define PATH_PURGE		"/purge"
#define PATH_TEMPORARY		"/temporary"
#define PATH_INCOMING		"/incoming"
#define PATH_ENVELOPES		"/envelopes"
#define PATH_MESSAGE		"/message"

/* number of MX records to lookup */
#define MAX_MX_COUNT		10

/* max response delay under flood conditions */
#define MAX_RESPONSE_DELAY	60

/* how many responses per state are undelayed */
#define FAST_RESPONSES		2

/* max len of any smtp line */
#define	SMTP_LINE_MAX		MAX_LINE_SIZE

#define F_STARTTLS		0x01
#define F_SMTPS			0x02
#define F_AUTH			0x04
#define F_SSL		       (F_SMTPS|F_STARTTLS)
#define	F_STARTTLS_REQUIRE	0x08
#define	F_AUTH_REQUIRE		0x10

#define	F_BACKUP		0x20	/* XXX - MUST BE SYNC-ED WITH ROUTE_BACKUP */

#define F_SCERT			0x01
#define F_CCERT			0x02

/* must match F_* for mta */
#define ROUTE_STARTTLS		0x01
#define ROUTE_SMTPS		0x02
#define ROUTE_SSL		(ROUTE_STARTTLS | ROUTE_SMTPS)
#define ROUTE_AUTH		0x04
#define ROUTE_MX		0x08
#define ROUTE_BACKUP		0x20	/* XXX - MUST BE SYNC-ED WITH F_BACKUP */

typedef uint32_t	objid_t;

SPLAY_HEAD(dict, dictentry);
SPLAY_HEAD(tree, treeentry);

#define	MAXPASSWORDLEN	128
struct userinfo {
	char username[MAXLOGNAME];
	char directory[MAXPATHLEN];
	char password[MAXPASSWORDLEN];
	uid_t uid;
	gid_t gid;
};

struct netaddr {
	struct sockaddr_storage ss;
	int bits;
};

struct relayhost {
	uint8_t flags;
	char hostname[MAXHOSTNAMELEN];
	uint16_t port;
	char cert[PATH_MAX];
	char authtable[MAX_PATH_SIZE];
};

struct imsg_queue_reply {
	uint64_t	id;
	int		success;
	uint64_t	evpid;
};

enum imsg_type {
	IMSG_NONE,
	IMSG_CTL_OK,		/* answer to smtpctl requests */
	IMSG_CTL_FAIL,
	IMSG_CTL_SHUTDOWN,
	IMSG_CTL_VERBOSE,
	IMSG_CONF_START,
	IMSG_CONF_SSL,
	IMSG_CONF_LISTENER,
	IMSG_CONF_TABLE,
	IMSG_CONF_TABLE_CONTENT,
	IMSG_CONF_RULE,
	IMSG_CONF_RULE_SOURCE,
	IMSG_CONF_FILTER,
	IMSG_CONF_END,

	IMSG_LKA_UPDATE_TABLE,

	IMSG_LKA_RCPT,
	IMSG_LKA_SECRET,
	IMSG_LKA_RULEMATCH,

	IMSG_MDA_SESS_NEW,
	IMSG_MDA_DONE,

	IMSG_MFA_CONNECT,
	IMSG_MFA_HELO,
	IMSG_MFA_MAIL,
	IMSG_MFA_RCPT,
	IMSG_MFA_DATALINE,
	IMSG_MFA_QUIT,
	IMSG_MFA_CLOSE,
	IMSG_MFA_RSET,

	IMSG_QUEUE_CREATE_MESSAGE,
	IMSG_QUEUE_SUBMIT_ENVELOPE,
	IMSG_QUEUE_COMMIT_ENVELOPES,
	IMSG_QUEUE_REMOVE_MESSAGE,
	IMSG_QUEUE_COMMIT_MESSAGE,

	IMSG_QUEUE_PAUSE_MDA,
	IMSG_QUEUE_PAUSE_MTA,
	IMSG_QUEUE_RESUME_MDA,
	IMSG_QUEUE_RESUME_MTA,

	IMSG_QUEUE_DELIVERY_OK,
	IMSG_QUEUE_DELIVERY_TEMPFAIL,
	IMSG_QUEUE_DELIVERY_PERMFAIL,
	IMSG_QUEUE_DELIVERY_LOOP,
	IMSG_QUEUE_MESSAGE_FD,
	IMSG_QUEUE_MESSAGE_FILE,
	IMSG_QUEUE_REMOVE,
	IMSG_QUEUE_EXPIRE,

	IMSG_SCHEDULER_MESSAGES,
	IMSG_SCHEDULER_ENVELOPES,
	IMSG_SCHEDULER_REMOVE,
	IMSG_SCHEDULER_SCHEDULE,

	IMSG_BATCH_CREATE,
	IMSG_BATCH_APPEND,
	IMSG_BATCH_CLOSE,

	IMSG_PARENT_FORWARD_OPEN,
	IMSG_PARENT_FORK_MDA,
	IMSG_PARENT_KILL_MDA,

	IMSG_PARENT_AUTHENTICATE,
	IMSG_PARENT_SEND_CONFIG,

	IMSG_SMTP_ENQUEUE,
	IMSG_SMTP_PAUSE,
	IMSG_SMTP_RESUME,

	IMSG_DNS_HOST,
	IMSG_DNS_HOST_END,
	IMSG_DNS_MX,
	IMSG_DNS_PTR,

	IMSG_STAT_INCREMENT,
	IMSG_STAT_DECREMENT,
	IMSG_STAT_SET,

	IMSG_DIGEST,
	IMSG_STATS,
	IMSG_STATS_GET,
};

enum blockmodes {
	BM_NORMAL,
	BM_NONBLOCK
};

struct imsgev {
	struct imsgbuf		 ibuf;
	void			(*handler)(int, short, void *);
	struct event		 ev;
	void			*data;
	int			 proc;
	short			 events;
};

struct ctl_id {
	objid_t		 id;
	char		 name[MAX_NAME_SIZE];
};

enum smtp_proc_type {
	PROC_PARENT = 0,
	PROC_SMTP,
	PROC_MFA,
	PROC_LKA,
	PROC_QUEUE,
	PROC_MDA,
	PROC_MTA,
	PROC_CONTROL,
	PROC_SCHEDULER,
} smtpd_process;

struct peer {
	enum smtp_proc_type	 id;
	void			(*cb)(int, short, void *);
};


enum table_type {
	T_NONE		= 0,
	T_DYNAMIC	= 0x01,	/* table with external source	*/
	T_LIST		= 0x02,	/* table holding a list		*/
	T_HASH		= 0x04,	/* table holding a hash table	*/
};

enum table_service {
	K_NONE		= 0x00,
	K_ALIAS		= 0x01,
	K_DOMAIN	= 0x02,
	K_VIRTUAL	= 0x04,
	K_CREDENTIALS	= 0x08,
	K_NETADDR	= 0x10,
	K_USERINFO	= 0x20,
};

struct table {
	char				 t_name[MAX_LINE_SIZE];
	objid_t				 t_id;
	enum table_type			 t_type;
	char				 t_src[MAX_TABLE_BACKEND_SIZE];
	char				 t_config[MAXPATHLEN];

	struct dict			 t_dict;

	void				*t_handle;
	struct table_backend		*t_backend;
	void				*t_payload;
};

struct table_backend {
	const unsigned int	services;
	int	(*config)(struct table *, const char *);
	void	*(*open)(struct table *);
	int	(*update)(struct table *);
	void	(*close)(void *);
	int	(*lookup)(void *, const char *, enum table_service, void **);
};


enum cond_type {
	COND_ANY,
	COND_DOM,
	COND_VDOM
};

struct cond {
	TAILQ_ENTRY(cond)		 c_entry;
	objid_t				 c_table;
	enum cond_type			 c_type;
};

enum action_type {
	A_RELAY,
	A_RELAYVIA,
	A_MAILDIR,
	A_MBOX,
	A_FILENAME,
	A_MDA
};

enum decision {
	R_REJECT,
	R_ACCEPT
};

struct rule {
	TAILQ_ENTRY(rule)		r_entry;
	enum decision			r_decision;
	char				r_tag[MAX_TAG_SIZE];
	int				r_accept;
	struct table		       *r_sources;
	struct cond			r_condition;
	enum action_type		r_action;
	union rule_dest {
		char			buffer[EXPAND_BUFFER];
		struct relayhost	relayhost;
	}				r_value;

	struct mailaddr		       *r_as;
	objid_t				r_atable;
	time_t				r_qexpire;
};

struct mailaddr {
	char	user[MAX_LOCALPART_SIZE];
	char	domain[MAX_DOMAINPART_SIZE];
};

enum delivery_type {
	D_MDA,
	D_MTA,
	D_BOUNCE
};

enum delivery_status {
	DS_PERMFAILURE	= 1,
	DS_TEMPFAILURE	= 2,
};

enum delivery_flags {
	DF_AUTHENTICATED	= 0x1,
	DF_BOUNCE		= 0x4,
	DF_INTERNAL		= 0x8, /* internal expansion forward */

	/* the remaining flags are not saved on disk */

	DF_PENDING		= 0x10,
	DF_INFLIGHT		= 0x20,
};

struct delivery_mda {
	enum action_type	method;
	struct userinfo		user;
	char			buffer[EXPAND_BUFFER];
};

struct delivery_mta {
	struct relayhost	relay;
};

enum expand_type {
	EXPAND_INVALID,
	EXPAND_USERNAME,
	EXPAND_FILENAME,
	EXPAND_FILTER,
	EXPAND_INCLUDE,
	EXPAND_ADDRESS
};

struct expandnode {
	RB_ENTRY(expandnode)	entry;
	TAILQ_ENTRY(expandnode)	tq_entry;
	enum expand_type	type;
	int			sameuser;
	int			alias;
	struct rule	       *rule;
	struct expandnode      *parent;
	unsigned int		depth;
	union {
		/*
		 * user field handles both expansion user and system user
		 * so we MUST make it large enough to fit a mailaddr user
		 */
		char		user[MAX_LOCALPART_SIZE];
		char		buffer[EXPAND_BUFFER];
		struct mailaddr	mailaddr;
	}			u;
};

struct expand {
	RB_HEAD(expandtree, expandnode)	 tree;
	TAILQ_HEAD(xnodes, expandnode)	*queue;
	int				 alias;
	struct rule			*rule;
	struct expandnode		*parent;
};

#define	SMTPD_ENVELOPE_VERSION		1
struct envelope {
	TAILQ_ENTRY(envelope)		entry;

	char				tag[MAX_TAG_SIZE];

	uint64_t			session_id;
	uint64_t			batch_id;

	uint32_t			version;
	uint64_t			id;
	enum delivery_type		type;

	char				helo[MAXHOSTNAMELEN];
	char				hostname[MAXHOSTNAMELEN];
	char				errorline[MAX_LINE_SIZE + 1];
	struct sockaddr_storage		ss;

	struct mailaddr			sender;
	struct mailaddr			rcpt;
	struct mailaddr			dest;

	union delivery_method {
		struct delivery_mda	mda;
		struct delivery_mta	mta;
	} agent;

	time_t				 creation;
	time_t				 lasttry;
	time_t				 expire;
	uint16_t			 retry;
	enum delivery_flags		 flags;
	time_t				 nexttry;
};

enum envelope_field {
	EVP_VERSION,
	EVP_MSGID,
	EVP_TYPE,
	EVP_HELO,
	EVP_HOSTNAME,
	EVP_ERRORLINE,
	EVP_SOCKADDR,
	EVP_SENDER,
	EVP_RCPT,
	EVP_DEST,
	EVP_CTIME,
	EVP_EXPIRE,
	EVP_RETRY,
	EVP_LASTTRY,
	EVP_FLAGS,
	EVP_MDA_METHOD,
	EVP_MDA_BUFFER,
	EVP_MDA_USER,
	EVP_MTA_RELAY_HOST,
	EVP_MTA_RELAY_PORT,
	EVP_MTA_RELAY_FLAGS,
	EVP_MTA_RELAY_CERT,
	EVP_MTA_RELAY_AUTHMAP,
	EVP_MTA_RELAY_AUTHTABLE
};


enum session_state {
	S_NEW = 0,
	S_CONNECTED,
	S_INIT,
	S_GREETED,
	S_TLS,
	S_AUTH_INIT,
	S_AUTH_USERNAME,
	S_AUTH_PASSWORD,
	S_AUTH_FINALIZE,
	S_RSET,
	S_HELO,
	S_MAIL_MFA,
	S_MAIL_QUEUE,
	S_MAIL,
	S_RCPT_MFA,
	S_RCPT,
	S_DATA,
	S_DATA_QUEUE,
	S_DATACONTENT,
	S_DONE,
	S_QUIT,
	S_CLOSE
};
#define STATE_COUNT	22

struct ssl {
	SPLAY_ENTRY(ssl)	 ssl_nodes;
	char			 ssl_name[PATH_MAX];
	char			*ssl_ca;
	off_t			 ssl_ca_len;
	char			*ssl_cert;
	off_t			 ssl_cert_len;
	char			*ssl_key;
	off_t			 ssl_key_len;
	char			*ssl_dhparams;
	off_t			 ssl_dhparams_len;
	uint8_t			 flags;
};

struct listener {
	uint8_t			 flags;
	int			 fd;
	struct sockaddr_storage	 ss;
	in_port_t		 port;
	struct timeval		 timeout;
	struct event		 ev;
	char			 ssl_cert_name[PATH_MAX];
	struct ssl		*ssl;
	void			*ssl_ctx;
	char			 tag[MAX_TAG_SIZE];
	TAILQ_ENTRY(listener)	 entry;
};

struct auth {
	uint64_t	 id;
	char		 user[MAXLOGNAME];
	char		 pass[MAX_LINE_SIZE + 1];
	int		 success;
};

enum session_flags {
	F_EHLO		= 0x01,
	F_8BITMIME	= 0x02,
	F_SECURE	= 0x04,
	F_AUTHENTICATED	= 0x08,
	F_WAITIMSG	= 0x10,
	F_ZOMBIE	= 0x20,
	F_KICK		= 0x40,
};

struct session {
	SPLAY_ENTRY(session)		 s_nodes;
	uint64_t			 s_id;

	struct iobuf			 s_iobuf;
	struct io			 s_io;

	enum session_flags		 s_flags;
	enum session_state		 s_state;
	struct sockaddr_storage		 s_ss;
	char				 s_hostname[MAXHOSTNAMELEN];
	struct event			 s_ev;
	struct listener			*s_l;
	struct timeval			 s_tv;
	struct envelope			 s_msg;
	short				 s_nresp[STATE_COUNT];

	char				 cmd[SMTP_LINE_MAX];
	size_t				 kickcount;
	size_t				 mailcount;
	size_t				 rcptcount;
	long				 s_datalen;

	struct auth			 s_auth;
	int				 s_dstatus;

	FILE				*datafp;
};


struct smtpd {
	char				sc_conffile[MAXPATHLEN];
	size_t				sc_maxsize;

#define SMTPD_OPT_VERBOSE		0x00000001
#define SMTPD_OPT_NOACTION		0x00000002
	uint32_t			sc_opts;
#define SMTPD_CONFIGURING		0x00000001
#define SMTPD_EXITING			0x00000002
#define SMTPD_MDA_PAUSED		0x00000004
#define SMTPD_MTA_PAUSED		0x00000008
#define SMTPD_SMTP_PAUSED		0x00000010
#define SMTPD_MDA_BUSY			0x00000020
#define SMTPD_MTA_BUSY			0x00000040
#define SMTPD_BOUNCE_BUSY		0x00000080
#define SMTPD_SMTP_DISABLED		0x00000100
	uint32_t			sc_flags;
	uint32_t			sc_queue_flags;
#define QUEUE_COMPRESS			0x00000001
	char			       *sc_queue_compress_algo;
	int				sc_qexpire;
	struct event			sc_ev;
	int			       *sc_pipes[PROC_COUNT][PROC_COUNT];
	struct imsgev		       *sc_ievs[PROC_COUNT];
	int				sc_instances[PROC_COUNT];
	int				sc_instance;
	char			       *sc_title[PROC_COUNT];
	struct passwd		       *sc_pw;
	char				sc_hostname[MAXHOSTNAMELEN];
	struct queue_backend	       *sc_queue;
	struct compress_backend	       *sc_compress;
	struct scheduler_backend       *sc_scheduler;
	struct stat_backend	       *sc_stat;

	time_t					 sc_uptime;

	TAILQ_HEAD(filterlist, filter)		*sc_filters;

	TAILQ_HEAD(listenerlist, listener)	*sc_listeners;

	TAILQ_HEAD(rulelist, rule)		*sc_rules, *sc_rules_reload;
	SPLAY_HEAD(sessiontree, session)	 sc_sessions;
	SPLAY_HEAD(ssltree, ssl)		*sc_ssl;
	SPLAY_HEAD(childtree, child)		 children;
	SPLAY_HEAD(lkatree, lka_session)	 lka_sessions;
	SPLAY_HEAD(mfatree, mfa_session)	 mfa_sessions;
	LIST_HEAD(mdalist, mda_session)		 mda_sessions;

	struct dict			       *sc_tables_dict;		/* keyed lookup	*/
	struct tree			       *sc_tables_tree;		/* id lookup	*/

	uint64_t				 filtermask;
};

#define	TRACE_VERBOSE	0x0001
#define	TRACE_IMSG	0x0002
#define	TRACE_IO	0x0004
#define	TRACE_SMTP	0x0008
#define	TRACE_MTA	0x0010
#define	TRACE_BOUNCE	0x0020
#define	TRACE_SCHEDULER	0x0040
#define	TRACE_STAT	0x0080
#define	TRACE_PROFILING	0x0100


struct submit_status {
	uint64_t			 id;
	int				 code;
	union submit_path {
		struct mailaddr		 maddr;
		uint32_t		 msgid;
		uint64_t		 evpid;
		char			 errormsg[MAX_LINE_SIZE + 1];
		char			 dataline[MAX_LINE_SIZE + 1];
	}				 u;
	enum delivery_flags		 flags;
	struct sockaddr_storage		 ss;
	struct envelope			 envelope;
};

struct forward_req {
	uint64_t			 id;
	uint8_t				 status;
	char				 as_user[MAXLOGNAME];
};

enum dns_status {
	DNS_OK = 0,
	DNS_RETRY,
	DNS_EINVAL,
	DNS_ENONAME,
	DNS_ENOTFOUND,
};

struct dns {
	uint64_t		 id;
	char			 host[MAXHOSTNAMELEN];
	char			 backup[MAXHOSTNAMELEN];
	int			 port;
	int			 error;
	int			 type;
	struct imsgev		*asker;
	struct sockaddr_storage	 ss;
};

struct secret {
	uint64_t		 id;
	char			 tablename[MAX_PATH_SIZE];
	char			 host[MAXHOSTNAMELEN];
	char			 secret[MAX_LINE_SIZE];
};

struct deliver {
	char			to[PATH_MAX];
	char			from[PATH_MAX];
	char			user[MAXLOGNAME];
	short			mode;
};

struct rulematch {
	uint64_t		 id;
	struct submit_status	 ss;
};

struct filter {
	TAILQ_ENTRY(filter)     f_entry;
	pid_t			pid;
	struct event		ev;
	struct imsgbuf		*ibuf;
	char			name[MAX_FILTER_NAME];
	char			path[MAXPATHLEN];
};

struct mfa_session {
	SPLAY_ENTRY(mfa_session)	 nodes;
	uint64_t			 id;

	enum session_state		 state;
	struct submit_status		 ss;
	struct filter			*filter;
	struct filter_msg		 fm;
};

struct mta_session;

struct mta_route {
	SPLAY_ENTRY(mta_route)	 entry;
	uint64_t		 id;

	uint8_t			 flags;
	char			*hostname;
	char			*backupname;
	uint16_t		 port;
	char			*cert;
	char			*auth;
	void			*ssl;

	/* route limits	*/
	int			 maxconn; 	/* in parallel */
	int			 maxmail;	/* per session */
	int			 maxrcpt;	/* per mail */

	int			 refcount;

	int			 ntask;
	TAILQ_HEAD(, mta_task)	 tasks;

	int			 nsession;

	int			 nfail;
	char			 errorline[64];
};

struct mta_task {
	TAILQ_ENTRY(mta_task)	 entry;
	struct mta_route	*route;
	uint32_t		 msgid;
	TAILQ_HEAD(, envelope)	 envelopes;
	struct mailaddr		 sender;
	struct mta_session	*session;
};

/* tables return structures */
struct table_credentials {
	char username[MAX_LINE_SIZE];
	char password[MAX_LINE_SIZE];
};

struct table_alias {
	size_t			nbnodes;
	struct expand		expand;
};

struct table_virtual {
	size_t			nbnodes;
	struct expand		expand;
};

struct table_netaddr {
	struct netaddr		netaddr;
};

struct table_domain {
	char			name[MAXHOSTNAMELEN];
};

struct table_relayhost {
	struct relayhost	relay;
};


/* XXX - must be == to struct userinfo ! */
struct table_userinfo {
	char username[MAXLOGNAME];
	char directory[MAXPATHLEN];
	char password[MAXPASSWORDLEN];
	uid_t uid;
	gid_t gid;
};

enum queue_op {
	QOP_CREATE,
	QOP_DELETE,
	QOP_UPDATE,
	QOP_LEARN,
	QOP_COMMIT,
	QOP_LOAD,
	QOP_FD_R,
	QOP_CORRUPT,
};

struct queue_backend {
	int	(*init)(int);
	int	(*message)(enum queue_op, uint32_t *);
	int	(*envelope)(enum queue_op, uint64_t *, char *, size_t);
};

struct compress_backend {
	int	(*compress_file)(FILE *, FILE *);
	int	(*uncompress_file)(FILE *, FILE *);
	size_t	(*compress_buffer)(char *, size_t, char *, size_t);
	size_t	(*uncompress_buffer)(char *, size_t, char *, size_t);
};

/* auth structures */
enum auth_type {
	AUTH_BSD,
	AUTH_PWD,
};

struct auth_backend {
	int	(*authenticate)(char *, char *);
};


/* delivery_backend */
struct delivery_backend {
	int	allow_root;
	void	(*open)(struct deliver *);
};

struct evpstate {
	uint64_t		evpid;
	uint16_t		flags;
	uint16_t		retry;
	time_t			time;
};

struct scheduler_info {
	uint64_t		evpid;
	enum delivery_type	type;
	time_t			creation;
	time_t			lasttry;
	time_t			expire;
	uint16_t		retry;
};

struct id_list {
	struct id_list	*next;
	uint64_t	 id;
};

#define SCHED_NONE		0x00
#define SCHED_DELAY		0x01
#define SCHED_REMOVE		0x02
#define SCHED_EXPIRE		0x04
#define SCHED_BOUNCE		0x08
#define SCHED_MDA		0x10
#define SCHED_MTA		0x20

struct scheduler_batch {
	int		 type;
	time_t		 delay;
	size_t		 evpcount;
	struct id_list	*evpids;
};

struct scheduler_backend {
	void	(*init)(void);

	void	(*insert)(struct scheduler_info *);
	size_t	(*commit)(uint32_t);
	size_t	(*rollback)(uint32_t);

	void	(*update)(struct scheduler_info *);
	void	(*delete)(uint64_t);

	void	(*batch)(int, struct scheduler_batch *);

	size_t	(*messages)(uint32_t, uint32_t *, size_t);
	size_t	(*envelopes)(uint64_t, struct evpstate *, size_t);
	void	(*schedule)(uint64_t);
	void	(*remove)(uint64_t);
};


enum stat_type {
	STAT_COUNTER,
	STAT_TIMESTAMP,
	STAT_TIMEVAL,
	STAT_TIMESPEC,
};

struct stat_value {
	enum stat_type	type;
	union stat_v {
		size_t		counter;
		time_t		timestamp;
		struct timeval	tv;
		struct timespec	ts;
	} u;
};

#define	STAT_KEY_SIZE	1024
struct stat_kv {
	void	*iter;
	char	key[STAT_KEY_SIZE];
	struct stat_value	val;
};

struct stat_backend {
	void	(*init)(void);
	void	(*close)(void);
	void	(*increment)(const char *, size_t);
	void	(*decrement)(const char *, size_t);
	void	(*set)(const char *, const struct stat_value *);
	int	(*iter)(void **, char **, struct stat_value *);
};

struct stat_digest {
	time_t			 startup;
	time_t			 timestamp;

	size_t			 clt_connect;
	size_t			 clt_disconnect;

	size_t			 evp_enqueued;
	size_t			 evp_dequeued;

	size_t			 evp_expired;
	size_t			 evp_removed;
	size_t			 evp_bounce;

	size_t			 dlv_ok;
	size_t			 dlv_permfail;
	size_t			 dlv_tempfail;
	size_t			 dlv_loop;
};

extern struct smtpd	*env;
extern void (*imsg_callback)(struct imsgev *, struct imsg *);


/* aliases.c */
int aliases_get(objid_t, struct expand *, const char *);
int aliases_virtual_get(objid_t, struct expand *, const struct mailaddr *);
int aliases_vdomain_exists(objid_t, const char *);
int alias_parse(struct expandnode *, char *);


/* auth.c */
struct auth_backend *auth_backend_lookup(enum auth_type);


/* bounce.c */
void bounce_add(uint64_t);
void bounce_run(uint64_t, int);


/* compress_backend.c */
struct compress_backend *compress_backend_lookup(const char *);
int compress_file(FILE *, FILE *);
int uncompress_file(FILE *, FILE *);
size_t compress_buffer(char *, size_t, char *, size_t);
size_t uncompress_buffer(char *, size_t, char *, size_t);


/* config.c */
#define PURGE_LISTENERS		0x01
#define PURGE_TABLES		0x02
#define PURGE_RULES		0x04
#define PURGE_SSL		0x08
#define PURGE_EVERYTHING	0xff
void purge_config(uint8_t);
void unconfigure(void);
void configure(void);
void init_pipes(void);
void config_pipes(struct peer *, uint);
void config_peers(struct peer *, uint);


/* control.c */
pid_t control(void);


/* delivery.c */
struct delivery_backend *delivery_backend_lookup(enum action_type);


/* dict.c */
#define dict_init(d) SPLAY_INIT((d))
#define dict_empty(d) SPLAY_EMPTY((d))
int dict_check(struct dict *, const char *);
void *dict_set(struct dict *, const char *, void *);
void dict_xset(struct dict *, const char *, void *);
void *dict_get(struct dict *, const char *);
void *dict_xget(struct dict *, const char *);
void *dict_pop(struct dict *, const char *);
void *dict_xpop(struct dict *, const char *);
int dict_poproot(struct dict *, const char * *, void **);
int dict_root(struct dict *, const char * *, void **);
int dict_iter(struct dict *, void **, const char * *, void **);
int dict_iterfrom(struct dict *, void **, const char *, const char **, void **);
void dict_merge(struct dict *, struct dict *);


/* dns.c */
void dns_query_host(char *, int, uint64_t);
void dns_query_mx(char *, char *, int, uint64_t);
void dns_query_ptr(struct sockaddr_storage *, uint64_t);
void dns_async(struct imsgev *, int, struct dns *);


/* enqueue.c */
int		 enqueue(int, char **);
int		 enqueue_offline(int, char **);


/* envelope.c */
void envelope_set_errormsg(struct envelope *, char *, ...);
char *envelope_ascii_field_name(enum envelope_field);
int envelope_ascii_load(enum envelope_field, struct envelope *, char *);
int envelope_ascii_dump(enum envelope_field, struct envelope *, char *, size_t);
int envelope_load_buffer(struct envelope *, char *, size_t);
int envelope_dump_buffer(struct envelope *, char *, size_t);


/* expand.c */
int expand_cmp(struct expandnode *, struct expandnode *);
void expand_insert(struct expand *, struct expandnode *);
struct expandnode *expand_lookup(struct expand *, struct expandnode *);
void expand_free(struct expand *);
RB_PROTOTYPE(expandtree, expandnode, nodes, expand_cmp);


/* forward.c */
int forwards_get(int, struct expand *);


/* lka.c */
pid_t lka(void);


/* lka_session.c */
void lka_session(struct submit_status *);
void lka_session_forward_reply(struct forward_req *, int);


/* mda.c */
pid_t mda(void);


/* mfa.c */
pid_t mfa(void);


/* mfa_session.c */
void mfa_session(struct submit_status *, enum session_state);


/* mta.c */
pid_t mta(void);
int mta_response_delivery(const char *);
const char *mta_response_prefix(const char *);
const char *mta_response_status(const char *);
const char *mta_response_text(const char *);
void mta_route_ok(struct mta_route *);
void mta_route_error(struct mta_route *, const char *);
void mta_route_collect(struct mta_route *);
const char *mta_route_to_text(struct mta_route *);


/* mta_session.c */
void mta_session(struct mta_route *);
void mta_session_imsg(struct imsgev *, struct imsg *);


/* parse.y */
int parse_config(struct smtpd *, const char *, int);
int cmdline_symset(char *);


/* queue.c */
pid_t queue(void);


/* queue_backend.c */
uint32_t queue_generate_msgid(void);
uint64_t queue_generate_evpid(uint32_t msgid);
struct queue_backend *queue_backend_lookup(const char *);
int queue_message_incoming_path(uint32_t, char *, size_t);
int queue_envelope_incoming_path(uint64_t, char *, size_t);
int queue_message_incoming_delete(uint32_t);
int queue_message_create(uint32_t *);
int queue_message_delete(uint32_t);
int queue_message_commit(uint32_t);
int queue_message_fd_r(uint32_t);
int queue_message_fd_rw(uint32_t);
int queue_message_corrupt(uint32_t);
int queue_envelope_create(struct envelope *);
int queue_envelope_delete(struct envelope *);
int queue_envelope_load(uint64_t, struct envelope *);
int queue_envelope_update(struct envelope *);
int queue_envelope_learn(struct envelope *);


/* ruleset.c */
struct rule *ruleset_match(const struct envelope *);


/* scheduler.c */
pid_t scheduler(void);


/* scheduler_bakend.c */
struct scheduler_backend *scheduler_backend_lookup(const char *);
void scheduler_info(struct scheduler_info *, struct envelope *);
time_t scheduler_compute_schedule(struct scheduler_info *);


/* smtp.c */
pid_t smtp(void);
void smtp_resume(void);
void smtp_destroy(struct session *);


/* smtp_session.c */
void session_init(struct listener *, struct session *);
int session_cmp(struct session *, struct session *);
void session_io(struct io *, int);
void session_pickup(struct session *, struct submit_status *);
void session_destroy(struct session *, const char *);
void session_respond(struct session *, char *, ...)
	__attribute__((format (printf, 2, 3)));
SPLAY_PROTOTYPE(sessiontree, session, s_nodes, session_cmp);


/* smtpd.c */
void imsg_event_add(struct imsgev *);
void imsg_compose_event(struct imsgev *, uint16_t, uint32_t, pid_t,
    int, void *, uint16_t);
void imsg_dispatch(int, short, void *);
const char * proc_to_str(int);
const char * imsg_to_str(int);


/* ssl.c */
void ssl_init(void);
int ssl_load_certfile(const char *, uint8_t);
void ssl_setup(struct listener *);
void *ssl_smtp_init(void *);
void *ssl_mta_init(struct ssl *);
const char *ssl_to_text(void *);
int ssl_cmp(struct ssl *, struct ssl *);
SPLAY_PROTOTYPE(ssltree, ssl, ssl_nodes, ssl_cmp);


/* ssl_privsep.c */
int	 ssl_ctx_use_private_key(void *, char *, off_t);
int	 ssl_ctx_use_certificate_chain(void *, char *, off_t);


/* stat_backend.c */
struct stat_backend	*stat_backend_lookup(const char *);
void	stat_increment(const char *, size_t);
void	stat_decrement(const char *, size_t);
void	stat_set(const char *, const struct stat_value *);
struct stat_value *stat_counter(size_t);
struct stat_value *stat_timestamp(time_t);
struct stat_value *stat_timeval(struct timeval *);
struct stat_value *stat_timespec(struct timespec *);


/* table.c */
void	table_open(struct table *);
void	table_update(struct table *);
void	table_close(struct table *);
int table_config_parser(struct table *, const char *);
int table_lookup(struct table *, const char *, enum table_service, void **);
struct table *table_find(objid_t);
struct table *table_findbyname(const char *);
struct table *table_create(const char *, const char *, const char *);
void table_destroy(struct table *);
void table_add(struct table *, const char *, const char *);
void table_delete(struct table *, const char *);
void table_delete_all(struct table *);
int table_netaddr_match(const char *, const char *);
void	table_open_all(void);
void	table_close_all(void);
void	table_set_payload(struct table *, void *);
void   *table_get_payload(struct table *);

/* tree.c */
#define tree_init(t) SPLAY_INIT((t))
#define tree_empty(t) SPLAY_EMPTY((t))
int tree_check(struct tree *, uint64_t);
void *tree_set(struct tree *, uint64_t, void *);
void tree_xset(struct tree *, uint64_t, void *);
void *tree_get(struct tree *, uint64_t);
void *tree_xget(struct tree *, uint64_t);
void *tree_pop(struct tree *, uint64_t);
void *tree_xpop(struct tree *, uint64_t);
int tree_poproot(struct tree *, uint64_t *, void **);
int tree_root(struct tree *, uint64_t *, void **);
int tree_iter(struct tree *, void **, uint64_t *, void **);
int tree_iterfrom(struct tree *, void **, uint64_t, uint64_t *, void **);
void tree_merge(struct tree *, struct tree *);


/* util.c */
typedef struct arglist arglist;
struct arglist {
	char	**list;
	uint	  num;
	uint	  nalloc;
};
void addargs(arglist *, char *, ...)
	__attribute__((format(printf, 2, 3)));
int bsnprintf(char *, size_t, const char *, ...)
	__attribute__((format (printf, 3, 4)));
int mkdirs(char *, mode_t);
int safe_fclose(FILE *);
int hostname_match(const char *, const char *);
int email_to_mailaddr(struct mailaddr *, char *);
int valid_localpart(const char *);
int valid_domainpart(const char *);
char *ss_to_text(const struct sockaddr_storage *);
char *time_to_text(time_t);
char *duration_to_text(time_t);
int secure_file(int, char *, char *, uid_t, int);
int  lowercase(char *, const char *, size_t);
void xlowercase(char *, const char *, size_t);
void sa_set_port(struct sockaddr *, int);
uint64_t generate_uid(void);
void fdlimit(double);
int availdesc(void);
uint32_t evpid_to_msgid(uint64_t);
uint64_t msgid_to_evpid(uint32_t);
int ckdir(const char *, mode_t, uid_t, gid_t, int);
int rmtree(char *, int);
int mvpurge(char *, char *);
int mktmpfile(void);
const char *parse_smtp_response(char *, size_t, char **, int *);
int text_to_netaddr(struct netaddr *, const char *);
int text_to_relayhost(struct relayhost *, const char *);
void *xmalloc(size_t, const char *);
void *xcalloc(size_t, size_t, const char *);
char *xstrdup(const char *, const char *);
void *xmemdup(const void *, size_t, const char *);
void iobuf_xinit(struct iobuf *, size_t, size_t, const char *);
void iobuf_xfqueue(struct iobuf *, const char *, const char *, ...);
void log_envelope(const struct envelope *, const char *, const char *,
    const char *);
void session_socket_blockmode(int, enum blockmodes);
void session_socket_no_linger(int);
int session_socket_error(int);
uint64_t strtoevpid(const char *);


/* waitq.c */
int  waitq_wait(void *, void (*)(void *, void *, void *), void *);
void waitq_run(void *, void *);
