/*	$OpenBSD: smtp_session.c,v 1.175 2012/11/12 14:58:53 eric Exp $	*/

/*
 * Copyright (c) 2008 Gilles Chehade <gilles@poolp.org>
 * Copyright (c) 2008 Pierre-Yves Ritschard <pyr@openbsd.org>
 * Copyright (c) 2008-2009 Jacek Masiulaniec <jacekm@dobremiasto.net>
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
#include <sys/uio.h>

#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <inttypes.h>
#include <openssl/ssl.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <vis.h>

#include "smtpd.h"
#include "log.h"

#define SMTP_LIMIT_MAIL		100
#define SMTP_LIMIT_RCPT		1000

#define SMTP_KICK_CMD		5
#define SMTP_KICK_RCPTFAIL	50

enum smtp_phase {
	PHASE_INIT = 0,
	PHASE_SETUP,
	PHASE_TRANSACTION
};

enum smtp_state {
	STATE_NEW = 0,
	STATE_CONNECTED,
	STATE_TLS,
	STATE_HELO,
	STATE_AUTH_INIT,
	STATE_AUTH_USERNAME,
	STATE_AUTH_PASSWORD,
	STATE_AUTH_FINALIZE,
	STATE_BODY,
	STATE_QUIT,
};

enum session_flags {
	SF_EHLO			= 0x0001,
	SF_8BITMIME		= 0x0002,
	SF_SECURE		= 0x0004,
	SF_AUTHENTICATED	= 0x0008,
	SF_BOUNCE		= 0x0010,
	SF_KICK			= 0x0020,
	SF_VERIFIED		= 0x0040,
};

enum message_flags {
	MF_QUEUE_ENVELOPE_FAIL	= 0x0001,
	MF_ERROR_SIZE		= 0x1000,
	MF_ERROR_IO		= 0x2000,
	MF_ERROR_MFA		= 0x4000,
};

enum smtp_command {
	CMD_HELO = 0,
	CMD_EHLO,
	CMD_STARTTLS,
	CMD_AUTH,
	CMD_MAIL_FROM,
	CMD_RCPT_TO,
	CMD_DATA,
	CMD_RSET,
	CMD_QUIT,
	CMD_HELP,
	CMD_NOOP,
};

struct smtp_session {
	uint64_t		 id;
	struct iobuf		 iobuf;
	struct io		 io;
	struct listener		*listener;
	struct sockaddr_storage	 ss;
	char			 hostname[MAXHOSTNAMELEN];

	int			 flags;
	int			 phase;
	enum smtp_state		 state;

	enum imsg_type		 mfa_imsg; /* last send */

	char			 helo[SMTP_LINE_MAX];
	char			 cmd[SMTP_LINE_MAX];

	struct auth		 auth;
	struct envelope		 evp;

	size_t			 kickcount;
	size_t			 mailcount;

	int			 msgflags;
	int			 msgcode;
	size_t			 rcptcount;
	size_t			 rcptfail;
	size_t			 destcount;

	FILE			*ofile;
	size_t			 datalen;
};

#define ADVERTISE_TLS(s) \
	((s)->listener->flags & F_STARTTLS && !((s)->flags & SF_SECURE))

#define ADVERTISE_AUTH(s) \
	((s)->listener->flags & F_AUTH && (s)->flags & SF_SECURE && \
	 !((s)->flags & SF_AUTHENTICATED))

static int smtp_mailaddr(struct mailaddr *, char *, int, char **);
static void smtp_session_init(void);
static void smtp_connected(struct smtp_session *);
static void smtp_mfa_response(struct smtp_session *, struct mfa_smtp_resp_msg *);
static void smtp_mfa_data(struct smtp_session *, char *);
static void smtp_io(struct io *, int);
static void smtp_enter_state(struct smtp_session *, int);
static void smtp_reply(struct smtp_session *, char *, ...);
static void smtp_command(struct smtp_session *, char *);
static int smtp_parse_mail_args(struct smtp_session *, char *);
static void smtp_rfc4954_auth_plain(struct smtp_session *, char *);
static void smtp_rfc4954_auth_login(struct smtp_session *, char *);
static void smtp_message_write(struct smtp_session *, char *);
static void smtp_message_end(struct smtp_session *);
static void smtp_message_reset(struct smtp_session *, int);
static void smtp_query_mfa(struct smtp_session *, int, void *, size_t);
static void smtp_free(struct smtp_session *, const char *);
static const char *smtp_strstate(int);
static int smtp_verify_certificate(struct smtp_session *);

static struct { int code; const char *cmd; } commands[] = {
	{ CMD_HELO,		"HELO" },
	{ CMD_EHLO,		"EHLO" },
	{ CMD_STARTTLS,		"STARTTLS" },
	{ CMD_AUTH,		"AUTH" },
	{ CMD_MAIL_FROM,	"MAIL FROM" },
	{ CMD_RCPT_TO,		"RCPT TO" },
	{ CMD_DATA,		"DATA" },
	{ CMD_RSET,		"RSET" },
	{ CMD_QUIT,		"QUIT" },
	{ CMD_HELP,		"HELP" },
	{ CMD_NOOP,		"NOOP" },
	{ -1, NULL },
};

static struct tree wait_lka_ptr;
static struct tree wait_lka_rcpt;
static struct tree wait_mfa_response;
static struct tree wait_mfa_data;
static struct tree wait_parent_auth;
static struct tree wait_queue_msg;
static struct tree wait_queue_fd;
static struct tree wait_queue_commit;
static struct tree wait_ssl_init;
static struct tree wait_ssl_verify;

static void
smtp_session_init(void)
{
	static int	init = 0;

	if (!init) {
		tree_init(&wait_lka_ptr);
		tree_init(&wait_lka_rcpt);
		tree_init(&wait_mfa_response);
		tree_init(&wait_mfa_data);
		tree_init(&wait_parent_auth);
		tree_init(&wait_queue_msg);
		tree_init(&wait_queue_fd);
		tree_init(&wait_queue_commit);
		tree_init(&wait_ssl_init);
		tree_init(&wait_ssl_verify);
		init = 1;
	}
}

int
smtp_session(struct listener *listener, int sock,
    const struct sockaddr_storage *ss, const char *hostname)
{
	struct smtp_session	*s;

	log_debug("debug: smtp: new client on listener: %p", listener);

	smtp_session_init();

	if ((s = calloc(1, sizeof(*s))) == NULL)
		return (-1);
	if (iobuf_init(&s->iobuf, MAX_LINE_SIZE, MAX_LINE_SIZE) == -1) {
		free(s);
		return (-1);
	}
	s->id = generate_uid();
	s->listener = listener;
	memmove(&s->ss, ss, sizeof(*ss));
	io_init(&s->io, sock, s, smtp_io, &s->iobuf);
	io_set_timeout(&s->io, SMTPD_SESSION_TIMEOUT * 1000);
	io_set_write(&s->io);

	s->state = STATE_NEW;
	s->phase = PHASE_INIT;

	/* For local enqueueing, the hostname is already set */
	if (hostname) {
		s->flags |= SF_AUTHENTICATED;
		/* A bit of a hack */
		if (!strcmp(hostname, "localhost"))
			s->flags |= SF_BOUNCE;
		strlcpy(s->hostname, hostname, sizeof(s->hostname));
		smtp_connected(s);
	} else {
		dns_query_ptr(s->id, (struct sockaddr *)&s->ss);
		tree_xset(&wait_lka_ptr, s->id, s);
	}

	return (0);
}

void
smtp_session_imsg(struct mproc *p, struct imsg *imsg)
{
	struct mfa_data_msg		*resp_mfa_data;
	struct mfa_smtp_resp_msg	*resp_mfa;
	struct queue_resp_msg		*resp_queue;
	struct lka_resp_msg		*resp_lka;
	struct dns_resp_msg		*resp_dns;
	struct ca_cert_resp_msg       	*resp_ca_cert;
	struct ca_vrfy_resp_msg       	*resp_ca_vrfy;
	struct mfa_req_msg		 req_mfa;
	struct smtp_session		*s;
	struct auth			*auth;
	void				*ssl;
	char				 user[MAXLOGNAME];

	switch (imsg->hdr.type) {
	case IMSG_DNS_PTR:
		resp_dns = imsg->data;
		s = tree_xpop(&wait_lka_ptr, resp_dns->reqid);
		if (resp_dns->error)
			strlcpy(s->hostname, "<unknown>", sizeof s->hostname);
		else
			strlcpy(s->hostname, resp_dns->u.ptr,
			    sizeof s->hostname);
		smtp_connected(s);
		return;

	case IMSG_LKA_EXPAND_RCPT:
		resp_lka = imsg->data;
		s = tree_xpop(&wait_lka_rcpt, resp_lka->reqid);
		switch (resp_lka->status) {
		case LKA_OK:
			fatalx("unexpected ok");
		case LKA_PERMFAIL:
			smtp_reply(s, "550 Invalid recipient");
			s->rcptfail += 1;
			if (s->rcptfail >= SMTP_KICK_RCPTFAIL) {
				log_info("smtp-in: Ending session %016"PRIx64
				    ": too many failed RCPT", s->id);
				smtp_enter_state(s, STATE_QUIT);
			}
			break;
		case LKA_TEMPFAIL:
			smtp_reply(s, "421 Temporary failure");
			smtp_enter_state(s, STATE_QUIT);
			break;
		}
		io_reload(&s->io);
		return;

	case IMSG_MFA_SMTP_DATA:
		resp_mfa_data = imsg->data;
		s = tree_xget(&wait_mfa_data, resp_mfa_data->reqid);
		smtp_mfa_data(s, resp_mfa_data->buffer);
		return;

	case IMSG_MFA_SMTP_RESPONSE:
		resp_mfa = imsg->data;
		s = tree_xpop(&wait_mfa_response, resp_mfa->reqid);
		smtp_mfa_response(s, resp_mfa);
		return;

	case IMSG_QUEUE_CREATE_MESSAGE:
		resp_queue = imsg->data;
		s = tree_xpop(&wait_queue_msg, resp_queue->reqid);
		if (resp_queue->success) {
			s->evp.id = resp_queue->evpid;
			s->rcptcount = 0;
			s->phase = PHASE_TRANSACTION;
			smtp_reply(s, "250 Ok");
		} else {
			smtp_reply(s, "421 Temporary Error");
		}
		io_reload(&s->io);
		return;

	case IMSG_QUEUE_MESSAGE_FILE:
		resp_queue = imsg->data;
		s = tree_xpop(&wait_queue_fd, resp_queue->reqid);
		if (!resp_queue->success) {
			smtp_reply(s, "421 Temporary Error");
			smtp_enter_state(s, STATE_QUIT);
			io_reload(&s->io);
			return;
		}
		if (imsg->fd == -1) {
			log_warnx("warn: Failed to retreive message fd");
			smtp_reply(s, "421 Temporary Error");
			smtp_enter_state(s, STATE_QUIT);
			io_reload(&s->io);
			return;
		}
		if ((s->ofile = fdopen(imsg->fd, "w")) == NULL) {
			log_warn("warn: Failed fdopen in smtp");
			close(imsg->fd);
			smtp_reply(s, "421 Temporary Error");
			smtp_enter_state(s, STATE_QUIT);
			io_reload(&s->io);
			return;
		}

		fprintf(s->ofile, "Received: from %s (%s [%s]);\n"
		    "\tby %s (OpenSMTPD) with %sSMTP id %08x;\n",
		    s->evp.helo,
		    s->hostname,
		    ss_to_text(&s->ss),
		    env->sc_hostname,
		    s->flags & SF_EHLO ? "E" : "",
		    evpid_to_msgid(s->evp.id));

		if (s->flags & SF_SECURE)
			fprintf(s->ofile,
			    "\tTLS version=%s cipher=%s bits=%d verify=%s;\n",
			    SSL_get_cipher_version(s->io.ssl),
			    SSL_get_cipher_name(s->io.ssl),
			    SSL_get_cipher_bits(s->io.ssl, NULL),
			    "NO");
			/* XXX - this can be uncommented when we *fully* verify */
			/*
			 *  (s->flags & SF_VERIFIED) ? "YES" :
			 *  (SSL_get_peer_certificate(s->io.ssl) ? "FAIL" : "NO"));
			 */

		if (s->rcptcount == 1)
			fprintf(s->ofile, "\tfor <%s@%s>;\n",
			    s->evp.rcpt.user,
			    s->evp.rcpt.domain);

		fprintf(s->ofile, "\t%s\n", time_to_text(time(NULL)));

		if (ferror(s->ofile)) {
			log_warnx("warn: Error on output file");
			smtp_reply(s, "421 Temporary Error");
			smtp_enter_state(s, STATE_QUIT);
			io_reload(&s->io);
			return;
		}

		smtp_enter_state(s, STATE_BODY);
		smtp_reply(s, "354 Enter mail, end with \".\""
		    " on a line by itself");

		tree_xset(&wait_mfa_data, s->id, s);
		io_reload(&s->io);
		return;

	case IMSG_QUEUE_SUBMIT_ENVELOPE:
		resp_queue = imsg->data;
		s = tree_xget(&wait_lka_rcpt, resp_queue->reqid);
		if (resp_queue->success)
			s->destcount++;
		else
			s->msgflags |= MF_QUEUE_ENVELOPE_FAIL;
		return;

	case IMSG_QUEUE_COMMIT_ENVELOPES:
		resp_queue = imsg->data;
		s = tree_xpop(&wait_lka_rcpt, resp_queue->reqid);
		/* This cannot fail. */
		if (!resp_queue->success)
			fatalx("commit failed: not supposed to happen");

		if (s->msgflags & MF_QUEUE_ENVELOPE_FAIL) {
			/*
			 * If an envelope failed, we can't cancel the last
			 * RCPT only so we must cancel the whole transaction
			 * and close the connection.
			 */
			smtp_reply(s, "421 Temporary failure");
			smtp_enter_state(s, STATE_QUIT);
		}
		else {
			s->rcptcount++;
			s->kickcount--;
			smtp_reply(s, "250 Recipient ok");
		}
		io_reload(&s->io);
		return;

	case IMSG_QUEUE_COMMIT_MESSAGE:
		resp_queue = imsg->data;
		s = tree_xpop(&wait_queue_commit, resp_queue->reqid);
		req_mfa.reqid = s->id;

		if (!resp_queue->success) {
			m_compose(p_mfa, IMSG_MFA_EVENT_ROLLBACK, 0, 0, -1,
			    &req_mfa, sizeof(req_mfa));
			smtp_reply(s, "421 Temporary failure");
			smtp_enter_state(s, STATE_QUIT);
			io_reload(&s->io);
			return;
		}
		m_compose(p_mfa, IMSG_MFA_EVENT_COMMIT, 0, 0, -1,
		    &req_mfa, sizeof(req_mfa));
		smtp_reply(s, "250 %08x Message accepted for delivery",
		    evpid_to_msgid(s->evp.id));
		log_info("smtp-in: Accepted message %08x on session %016"PRIx64
		    ": from=<%s%s%s>, size=%zu, nrcpts=%zu, proto=%s",
		    evpid_to_msgid(s->evp.id),
		    s->id,
		    s->evp.sender.user,
		    s->evp.sender.user[0] == '\0' ? "" : "@",
		    s->evp.sender.domain,
		    s->datalen,
		    s->rcptcount,
		    s->flags & SF_EHLO ? "ESMTP" : "SMTP");

		s->mailcount++;
		s->kickcount = 0;
		s->phase = PHASE_SETUP;
		smtp_message_reset(s, 0);
		smtp_enter_state(s, STATE_HELO);
		io_reload(&s->io);
		return;

	case IMSG_LKA_AUTHENTICATE:
		auth = imsg->data;
		s = tree_xpop(&wait_parent_auth, auth->id);
		strnvis(user, auth->user, sizeof user, VIS_WHITE | VIS_SAFE);
		if (auth->success == 0) {
			log_info("smtp-in: Authentication failed for user %s "
			    "on session %016"PRIx64, user, s->id);
			smtp_reply(s, "535 Authentication failed");
		}
		else if (auth->success) {
			log_info("smtp-in: Accepted authentication for user %s "
			    "on session %016"PRIx64, user, s->id);
			s->kickcount = 0;
			s->flags |= SF_AUTHENTICATED;
			smtp_reply(s, "235 Authentication succeeded");
		}
		else {
			log_info("smtp-in: Authentication temporarily failed "
			    "for user %s on session %016"PRIx64, user, s->id);
			smtp_reply(s, "421 Temporary failure");
		}
		smtp_enter_state(s, STATE_HELO);
		io_reload(&s->io);
		return;

	case IMSG_LKA_SSL_INIT:
		resp_ca_cert = imsg->data;
		s = tree_xpop(&wait_ssl_init, resp_ca_cert->reqid);

		if (resp_ca_cert->status == CA_FAIL) {
			log_info("smtp-in: Disconnecting session %016" PRIx64
			    ": CA failure", s->id);
			smtp_free(s, "CA failure");	
			return;
		}

		resp_ca_cert = xmemdup(imsg->data, sizeof *resp_ca_cert, "smtp:ca_cert");
		if (resp_ca_cert == NULL)
			fatal(NULL);
		resp_ca_cert->cert = xstrdup((char *)imsg->data +
		    sizeof *resp_ca_cert, "smtp:ca_cert");

		resp_ca_cert->key = xstrdup((char *)imsg->data +
		    sizeof *resp_ca_cert + resp_ca_cert->cert_len,
		    "smtp:ca_key");

		ssl = ssl_smtp_init(s->listener->ssl_ctx,
		    resp_ca_cert->cert, resp_ca_cert->cert_len,
		    resp_ca_cert->key, resp_ca_cert->key_len);
		io_set_read(&s->io);
		io_start_tls(&s->io, ssl);

		bzero(resp_ca_cert->cert, resp_ca_cert->cert_len);
		bzero(resp_ca_cert->key, resp_ca_cert->key_len);
		free(resp_ca_cert);
		return;

	case IMSG_LKA_SSL_VERIFY:
		resp_ca_vrfy = imsg->data;
		s = tree_xpop(&wait_ssl_verify, resp_ca_vrfy->reqid);

		if (resp_ca_vrfy->status == CA_OK)
			s->flags |= SF_VERIFIED;

		smtp_io(&s->io, IO_TLSVERIFIED);
		io_resume(&s->io, IO_PAUSE_IN);
		return;
	}

	log_warnx("smtp_session_imsg: unexpected %s imsg",
	    imsg_to_str(imsg->hdr.type));
	fatalx(NULL);
}

static void
smtp_mfa_response(struct smtp_session *s, struct mfa_smtp_resp_msg *resp)
{
	struct ca_cert_req_msg		 req_ca_cert;
	struct queue_req_msg		 req_queue;
	struct lka_expand_msg		 req_lka;
	const char			*line;
	uint32_t			 code;

	code = resp->code ? resp->code : 0;
	line = resp->line[0] ? resp->line : NULL;

	if (resp->status == MFA_CLOSE) {
		code = code ? code : 421;
		line = line ? line : "Temporary failure";
		smtp_reply(s, "%d %s", code, line);
		smtp_enter_state(s, STATE_QUIT);
		io_reload(&s->io);
		return;
	}

	switch (s->mfa_imsg) {

	case IMSG_MFA_REQ_CONNECT:
		if (resp->status != MFA_OK) {
			log_info("smtp-in: Disconnecting session %016" PRIx64
			    ": rejected by filter", s->id);
			smtp_free(s, "rejected by filter");
			return;
		}

		if (s->listener->flags & F_SMTPS) {
			req_ca_cert.reqid = s->id;
			strlcpy(req_ca_cert.name, s->listener->ssl_cert_name,
			    sizeof req_ca_cert.name);
			m_compose(p_lka, IMSG_LKA_SSL_INIT, 0, 0, -1,
			    &req_ca_cert, sizeof(req_ca_cert));
			tree_xset(&wait_ssl_init, s->id, s);
			return;
		}
		smtp_reply(s, SMTPD_BANNER, env->sc_hostname);
		io_reload(&s->io);
		return;

	case IMSG_MFA_REQ_HELO:
		if (resp->status != MFA_OK) {
			code = code ? code : 530;
			line = line ? line : "Hello rejected";
			smtp_reply(s, "%d %s", code, line);
			io_reload(&s->io);
			return;
		}

		smtp_enter_state(s, STATE_HELO);
		smtp_reply(s, "250%c%s Hello %s [%s], pleased to meet you",
		    (s->flags & SF_EHLO) ? '-' : ' ',
		    env->sc_hostname,
		    s->evp.helo,
		    ss_to_text(&s->ss));

		if (s->flags & SF_EHLO) {
			smtp_reply(s, "250-8BITMIME");
			smtp_reply(s, "250-ENHANCEDSTATUSCODES");
			smtp_reply(s, "250-SIZE %zu", env->sc_maxsize);
			if (ADVERTISE_TLS(s))
				smtp_reply(s, "250-STARTTLS");
			if (ADVERTISE_AUTH(s))
				smtp_reply(s, "250-AUTH PLAIN LOGIN");
			smtp_reply(s, "250 HELP");
		}
		s->kickcount = 0;
		s->phase = PHASE_SETUP;
		io_reload(&s->io);
		return;

	case IMSG_MFA_REQ_MAIL:
		if (resp->status != MFA_OK) {
			code = code ? code : 530;
			line = line ? line : "Sender rejected";
			smtp_reply(s, "%d %s", code, line);
			io_reload(&s->io);
			return;
		}
		req_queue.reqid = s->id;
		req_queue.evpid = 0;
		m_compose(p_queue, IMSG_QUEUE_CREATE_MESSAGE, 0, 0, -1,
		    &req_queue, sizeof(req_queue));
		tree_xset(&wait_queue_msg, s->id, s);
		return;

	case IMSG_MFA_REQ_RCPT:
		if (resp->status != MFA_OK) {
			code = code ? code : 530;
			line = line ? line : "Recipient rejected";
			smtp_reply(s, "%d %s", code, line);

			s->rcptfail += 1;
			if (s->rcptfail >= SMTP_KICK_RCPTFAIL) {
				log_info("smtp-in: Ending session %016" PRIx64
				    ": too many failed RCPT", s->id);
				smtp_enter_state(s, STATE_QUIT);
			}
			io_reload(&s->io);
			return;
		}
		req_lka.reqid = s->id;
		req_lka.evp = s->evp;
		m_compose(p_lka, IMSG_LKA_EXPAND_RCPT, 0, 0, -1,
		    &req_lka, sizeof(req_lka));
		tree_xset(&wait_lka_rcpt, s->id, s);
		return;

	case IMSG_MFA_REQ_DATA:
		if (resp->status != MFA_OK) {
			code = code ? code : 530;
			line = line ? line : "Message rejected";
			smtp_reply(s, "%d %s", code, line);
			io_reload(&s->io);
			return;
		}
		req_queue.reqid = s->id;
		req_queue.evpid = s->evp.id;
		m_compose(p_queue, IMSG_QUEUE_MESSAGE_FILE, 0, 0, -1,
		    &req_queue, sizeof(req_queue));
		tree_xset(&wait_queue_fd, s->id, s);
		return;

	case IMSG_MFA_REQ_EOM:
		if (resp->status != MFA_OK) {
			code = code ? code : 530;
			line = line ? line : "Message rejected";
			smtp_reply(s, "%d %s", code, line);
			io_reload(&s->io);
			return;
		}
		smtp_message_end(s);
		return;

	default:
		fatal("bad mfa_imsg");
	}
}


static void
smtp_mfa_data(struct smtp_session *s, char *buffer)
{
	smtp_message_write(s, buffer);
}

static void
smtp_io(struct io *io, int evt)
{
	struct ca_cert_req_msg	req_ca_cert;
	struct mfa_data_msg	req;
	struct smtp_session    *s = io->arg;
	char		       *line;
	size_t			len;

	log_trace(TRACE_IO, "smtp: %p: %s %s", s, io_strevent(evt),
	    io_strio(io));

	switch (evt) {

	case IO_TLSREADY:
		log_info("smtp-in: Started TLS on session %016"PRIx64": %s",
		    s->id, ssl_to_text(s->io.ssl));

		s->flags |= SF_SECURE;
		s->kickcount = 0;
		s->phase = PHASE_INIT;

		if (smtp_verify_certificate(s)) {
			io_pause(&s->io, IO_PAUSE_IN);
			break;
		}

		/* No verification required, cascade */

	case IO_TLSVERIFIED:
		if (SSL_get_peer_certificate(s->io.ssl))
			log_info("smtp-in: Client certificate verification %s "
			    "on session %016"PRIx64,
			    (s->flags & SF_VERIFIED) ? "succeeded" : "failed",
			    s->id);

		if (s->listener->flags & F_SMTPS) {
			stat_increment("smtp.smtps", 1);
			smtp_reply(s, SMTPD_BANNER, env->sc_hostname);
			io_set_write(&s->io);
		}
		else {
			stat_increment("smtp.tls", 1);
			smtp_enter_state(s, STATE_HELO);
		}
		break;

	case IO_DATAIN:
	    nextline:
		line = iobuf_getline(&s->iobuf, &len);
		if ((line == NULL && iobuf_len(&s->iobuf) >= SMTP_LINE_MAX) ||
		    (line && len >= SMTP_LINE_MAX)) {
			smtp_reply(s, "500 Line too long");
			smtp_enter_state(s, STATE_QUIT);
			io_set_write(io);
			return;
		}

		/* No complete line received */
		if (line == NULL) {
			iobuf_normalize(&s->iobuf);
			return;
		}

		/* Message body */
		if (s->state == STATE_BODY && strcmp(line, ".")) {
			req.reqid = s->id;
			req.flags = s->flags;
			len = strlcpy(req.buffer, line, sizeof(req.buffer));
			if (len >= (sizeof req.buffer))
				fatalx("overflow in smtp_io()");
			m_compose(p_mfa, IMSG_MFA_SMTP_DATA, 0, 0, -1,
			    &req, sizeof(req));
			goto nextline;
		}

		/* Pipelining not supported */
		if (iobuf_len(&s->iobuf)) {
			smtp_reply(s, "500 Pipelining not supported");
			smtp_enter_state(s, STATE_QUIT);
			io_set_write(io);
			return;
		}

		/* End of body */
		if (s->state == STATE_BODY) {
			iobuf_normalize(&s->iobuf);
			io_set_write(io);
			req.reqid = s->id;
			smtp_query_mfa(s, IMSG_MFA_REQ_EOM, &req, sizeof(req));
			return;
		}

		/* Must be a command */
		strlcpy(s->cmd, line, sizeof s->cmd);
		io_set_write(io);
		smtp_command(s, line);
		iobuf_normalize(&s->iobuf);
		if (s->flags & SF_KICK)
			smtp_free(s, "kick");
		break;

	case IO_LOWAT:
		if (s->state == STATE_QUIT) {
			log_info("smtp-in: Closing session %016" PRIx64, s->id);
			smtp_free(s, "done");
			break;
		}


		/* Wait for the client to start tls */
		if (s->state == STATE_TLS) {
			req_ca_cert.reqid = s->id;
			strlcpy(req_ca_cert.name, s->listener->ssl_cert_name,
			    sizeof req_ca_cert.name);
			m_compose(p_lka, IMSG_LKA_SSL_INIT, 0, 0, -1,
			    &req_ca_cert, sizeof(req_ca_cert));
			tree_xset(&wait_ssl_init, s->id, s);
			break;
		}

		io_set_read(io);
		break;

	case IO_TIMEOUT:
		log_info("smtp-in: Disconnecting session %016"PRIx64": "
		    "session timeout", s->id);
		smtp_free(s, "timeout");
		break;

	case IO_DISCONNECTED:
		log_info("smtp-in: Received disconnect from session %016"PRIx64,
		    s->id);
		smtp_free(s, "disconnected");
		break;

	case IO_ERROR:
		log_info("smtp-in: Disconnecting session %016"PRIx64": "
		    "IO error: %s", s->id, io->error);
		smtp_free(s, "IO error");
		break;

	default:
		fatalx("smtp_io()");
	}
}

static void
smtp_command(struct smtp_session *s, char *line)
{
	struct queue_req_msg	 req_queue;
	struct mfa_req_msg	 req_mfa;
	struct mfa_line_msg	 req_line;
	struct mfa_maddr_msg	 req_maddr;
	char			*args, *eom, *method;
	int			 cmd, i;
	size_t			 len;

	log_trace(TRACE_SMTP, "smtp: %p: <<< %s", s, line);

	if (++s->kickcount >= SMTP_KICK_CMD) {
		log_info("smtp-in: Disconnecting session %016" PRIx64
		    ": session not moving forward", s->id);
		s->flags |= SF_KICK;
		stat_increment("smtp.kick", 1);
		return;
	}

	/*
	 * These states are special.
	 */
	if (s->state == STATE_AUTH_INIT) {
		smtp_rfc4954_auth_plain(s, line);
		return;
	}
	if (s->state == STATE_AUTH_USERNAME || s->state == STATE_AUTH_PASSWORD) {
		smtp_rfc4954_auth_login(s, line);
		return;
	}

	/*
	 * Unlike other commands, "mail from" and "rcpt to" contain a
	 * space in the command name.
	 */
	if (strncasecmp("mail from:", line, 10) == 0 ||
	    strncasecmp("rcpt to:", line, 8) == 0)
		args = strchr(line, ':');
	else
		args = strchr(line, ' ');

	if (args) {
		*args++ = '\0';
		while (isspace((int)*args))
			args++;
	}

	cmd = -1;
	for (i = 0; commands[i].code != -1; i++)
		if (!strcasecmp(line, commands[i].cmd)) {
			cmd = commands[i].code;
			break;
		}

	switch (cmd) {
	/*
	 * INIT
	 */
	case CMD_HELO:
	case CMD_EHLO:
		if (s->phase != PHASE_INIT) {
			smtp_reply(s, "503 Already indentified");
			break;
		}

		if (args == NULL) {
			smtp_reply(s, "501 %s requires domain address",
			    (cmd == CMD_HELO) ? "HELO" : "EHLO");
			break;
		}

		if (!valid_domainpart(args)) {
			smtp_reply(s, "501 Invalid domain name");
			break;
		}
		strlcpy(s->helo, args, sizeof(s->helo));
		s->flags &= SF_SECURE | SF_AUTHENTICATED | SF_VERIFIED;
		if (cmd == CMD_EHLO) {
			s->flags |= SF_EHLO;
			s->flags |= SF_8BITMIME;
		}

		smtp_message_reset(s, 1);
		req_line.reqid = s->id;
		req_line.flags = s->flags;
		len = strlcpy(req_line.line, s->helo, sizeof(req_line.line));
		smtp_query_mfa(s, IMSG_MFA_REQ_HELO, &req_line,
		    sizeof(req_line));
		break;
	/*
	 * SETUP
	 */
	case CMD_STARTTLS:
		if (s->phase != PHASE_SETUP) {
			smtp_reply(s, "503 Command not allowed at this point.");
			break;
		}

		if (!(s->listener->flags & F_STARTTLS)) {
			smtp_reply(s, "503 Command not supported");
			break;
		}

		if (s->flags & SF_SECURE) {
			smtp_reply(s, "503 Channel already secured");
			break;
		}
		if (args != NULL) {
			smtp_reply(s, "501 No parameters allowed");
			break;
		}
		smtp_reply(s, "220 Ready to start TLS");
		smtp_enter_state(s, STATE_TLS);
		break;

	case CMD_AUTH:
		if (s->phase != PHASE_SETUP) {
			smtp_reply(s, "503 Command not allowed at this point.");
			break;
		}

		if (s->flags & SF_AUTHENTICATED) {
			smtp_reply(s, "503 Already authenticated");
			break;
		}

		if (!ADVERTISE_AUTH(s)) {
			smtp_reply(s, "503 Command not supported");
			break;
		}

		if (args == NULL) {
			smtp_reply(s, "501 No parameters given");
			break;
		}

		method = args;
		eom = strchr(args, ' ');
		if (eom == NULL)
			eom = strchr(args, '\t');
		if (eom != NULL)
			*eom++ = '\0';
		if (strcasecmp(method, "PLAIN") == 0)
			smtp_rfc4954_auth_plain(s, eom);
		else if (strcasecmp(method, "LOGIN") == 0)
			smtp_rfc4954_auth_login(s, eom);
		else
			smtp_reply(s, "504 AUTH method \"%s\" not supported",
			    method);
		break;

	case CMD_MAIL_FROM:
		if (s->phase != PHASE_SETUP) {
			smtp_reply(s, "503 Command not allowed at this point.");
			break;
		}

		if (s->listener->flags & F_STARTTLS_REQUIRE &&
		    !(s->flags & SF_SECURE)) {
			smtp_reply(s,
			    "530 Must issue a STARTTLS command first");
			break;
		}

		if (s->listener->flags & F_AUTH_REQUIRE &&
		    !(s->flags & SF_AUTHENTICATED)) {
			smtp_reply(s,
			    "530 Must issue an AUTH command first");
			break;
		}

		if (s->mailcount >= SMTP_LIMIT_MAIL) {
			smtp_reply(s, "452 Too many messages sent");
			break;
		}

		smtp_message_reset(s, 1);

		if (smtp_mailaddr(&s->evp.sender, args, 1, &args) == 0) {
			smtp_reply(s, "553 Sender address syntax error");
			break;
		}
		if (args && smtp_parse_mail_args(s, args) == -1)
			break;

		req_maddr.reqid = s->id;
		req_maddr.flags = s->flags;
		req_maddr.maddr = s->evp.sender;
		smtp_query_mfa(s, IMSG_MFA_REQ_MAIL, &req_maddr,
		    sizeof(req_maddr));
		break;
	/*
	 * TRANSACTION
	 */
	case CMD_RCPT_TO:
		if (s->phase != PHASE_TRANSACTION) {
			smtp_reply(s, "503 Command not allowed at this point.");
			break;
		}

		if (s->rcptcount >= SMTP_LIMIT_RCPT) {
			smtp_reply(s, "452 Too many recipients");
			break;
		}

		if (smtp_mailaddr(&s->evp.rcpt, args, 0, &args) == 0) {
			smtp_reply(s,
			    "553 Recipient address syntax error");
			break;
		}
		if (*args) {
			smtp_reply(s,
			    "553 No option supported on RCPT TO");
			break;
		}

		req_maddr.reqid = s->id;
		req_maddr.flags = s->flags;
		req_maddr.maddr = s->evp.rcpt;
		smtp_query_mfa(s, IMSG_MFA_REQ_RCPT, &req_maddr,
		    sizeof(req_maddr));
		break;

	case CMD_RSET:
		if (s->phase != PHASE_TRANSACTION && s->phase != PHASE_SETUP) {
			smtp_reply(s, "503 Command not allowed at this point.");
			break;
		}
		req_mfa.reqid = s->id;
		m_compose(p_mfa, IMSG_MFA_EVENT_RSET, 0, 0, -1,
		     &req_mfa, sizeof(req_mfa));

		if (s->evp.id) {
			req_queue.reqid = s->id;
			req_queue.evpid = s->evp.id;
			m_compose(p_queue, IMSG_QUEUE_REMOVE_MESSAGE, 0, 0, -1,
			    &req_queue, sizeof(req_queue));
		}

		s->phase = PHASE_SETUP;
		if (s->ofile)
			fclose(s->ofile);
		smtp_message_reset(s, 0);
		smtp_reply(s, "250 2.0.0 Reset state");
		break;

	case CMD_DATA:
		if (s->phase != PHASE_TRANSACTION) {
			smtp_reply(s, "503 Command not allowed at this point.");
			break;
		}
		if (s->rcptcount == 0) {
			smtp_reply(s, "503 5.5.1 No recipient specified");
			break;
		}

		req_mfa.reqid = s->id;
		smtp_query_mfa(s, IMSG_MFA_REQ_DATA, &req_mfa, sizeof(req_mfa));
		break;
	/*
	 * ANY
	 */
	case CMD_QUIT:
		smtp_reply(s, "221 Bye");
		smtp_enter_state(s, STATE_QUIT);
		break;

	case CMD_NOOP:
		smtp_reply(s, "250 Ok");
		break;

	case CMD_HELP:
		smtp_reply(s, "214- This is OpenSMTPD");
		smtp_reply(s, "214- To report bugs in the implementation, "
		    "please contact bugs@openbsd.org");
		smtp_reply(s, "214- with full details");
		smtp_reply(s, "214 End of HELP info");
		break;

	default:
		smtp_reply(s, "500 Command unrecognized");
		break;
	}
}

static void
smtp_rfc4954_auth_plain(struct smtp_session *s, char *arg)
{
	struct auth	*a = &s->auth;
	char		 buf[1024], *user, *pass;
	int		 len;

	switch (s->state) {
	case STATE_HELO:
		if (arg == NULL) {
			smtp_enter_state(s, STATE_AUTH_INIT);
			smtp_reply(s, "334 ");
			return;
		}
		smtp_enter_state(s, STATE_AUTH_INIT);
		/* FALLTHROUGH */

	case STATE_AUTH_INIT:
		/* String is not NUL terminated, leave room. */
		if ((len = __b64_pton(arg, (unsigned char *)buf,
			    sizeof(buf) - 1)) == -1)
			goto abort;
		/* buf is a byte string, NUL terminate. */
		buf[len] = '\0';

		/*
		 * Skip "foo" in "foo\0user\0pass", if present.
		 */
		user = memchr(buf, '\0', len);
		if (user == NULL || user >= buf + len - 2)
			goto abort;
		user++; /* skip NUL */
		if (strlcpy(a->user, user, sizeof(a->user)) >= sizeof(a->user))
			goto abort;

		pass = memchr(user, '\0', len - (user - buf));
		if (pass == NULL || pass >= buf + len - 2)
			goto abort;
		pass++; /* skip NUL */
		if (strlcpy(a->pass, pass, sizeof(a->pass)) >= sizeof(a->pass))
			goto abort;

		a->id = s->id;
		strlcpy(a->authtable, s->listener->authtable, sizeof a->authtable);
		m_compose(p_lka, IMSG_LKA_AUTHENTICATE, 0, 0, -1, a, sizeof(*a));
		bzero(a->pass, sizeof(a->pass));
		tree_xset(&wait_parent_auth, s->id, s);
		return;

	default:
		fatal("smtp_rfc4954_auth_plain: unknown state");
	}

abort:
	smtp_reply(s, "501 Syntax error");
	smtp_enter_state(s, STATE_HELO);
}

static void
smtp_rfc4954_auth_login(struct smtp_session *s, char *arg)
{
	struct auth	*a = &s->auth;

	switch (s->state) {
	case STATE_HELO:
		smtp_enter_state(s, STATE_AUTH_USERNAME);
		smtp_reply(s, "334 VXNlcm5hbWU6");
		return;

	case STATE_AUTH_USERNAME:
		bzero(a->user, sizeof(a->user));
		if (__b64_pton(arg, (unsigned char *)a->user,
			sizeof(a->user) - 1) == -1)
			goto abort;

		smtp_enter_state(s, STATE_AUTH_PASSWORD);
		smtp_reply(s, "334 UGFzc3dvcmQ6");
		return;

	case STATE_AUTH_PASSWORD:
		bzero(a->pass, sizeof(a->pass));
		if (__b64_pton(arg, (unsigned char *)a->pass,
			sizeof(a->pass) - 1) == -1)
			goto abort;

		a->id = s->id;
		strlcpy(a->authtable, s->listener->authtable, sizeof a->authtable);
		m_compose(p_lka, IMSG_LKA_AUTHENTICATE, 0, 0, -1, a, sizeof(*a));
		bzero(a->pass, sizeof(a->pass));
		tree_xset(&wait_parent_auth, s->id, s);
		return;

	default:
		fatal("smtp_rfc4954_auth_login: unknown state");
	}

abort:
	smtp_reply(s, "501 Syntax error");
	smtp_enter_state(s, STATE_HELO);
}

static int
smtp_parse_mail_args(struct smtp_session *s, char *args)
{
	char *b;

	while ((b = strsep(&args, " "))) {
		if (*b == '\0')
			continue;

		if (strncasecmp(b, "AUTH=", 5) == 0)
			log_debug("debug: smtp: AUTH in MAIL FROM command");
		else if (strncasecmp(b, "SIZE=", 5) == 0)
			log_debug("debug: smtp: SIZE in MAIL FROM command");
		else if (!strcasecmp(b, "BODY=7BIT"))
			/* XXX only for this transaction */
			s->flags &= ~SF_8BITMIME;
		else if (strcasecmp(b, "BODY=8BITMIME") == 0)
			;
		else {
			smtp_reply(s, "503 Unsupported option %s", b);
			return (-1);
		}
	}

	return (0);
}

static void
smtp_connected(struct smtp_session *s)
{
	struct mfa_connect_msg	req;
	socklen_t		sl;

	smtp_enter_state(s, STATE_CONNECTED);
	log_info("smtp-in: New session %016"PRIx64" from host %s [%s]",
	    s->id, s->hostname, ss_to_text(&s->ss));
	req.reqid = s->id;
	req.remote = s->ss;
	sl = sizeof(req.local);
	getsockname(s->io.sock, (struct sockaddr*)&req.local, &sl);
	strlcpy(req.hostname, s->hostname, sizeof(req.hostname));
	smtp_query_mfa(s, IMSG_MFA_REQ_CONNECT, &req, sizeof(req));
}

void
smtp_enter_state(struct smtp_session *s, int newstate)
{
	log_trace(TRACE_SMTP, "smtp: %p: %s -> %s", s,
	    smtp_strstate(s->state),
	    smtp_strstate(newstate));

	s->state = newstate;
}

static void
smtp_message_write(struct smtp_session *s, char *line)
{
	size_t i, len;

	log_trace(TRACE_SMTP, "<<< [MSG] %s", line);

	/* Don't waste resources on message if it's going to bin anyway. */
	if (s->msgflags & (MF_ERROR_IO | MF_ERROR_SIZE))
		return;

	/*
	 * "If the first character is a period and there are other characters
	 *  on the line, the first character is deleted." [4.5.2]
	 */
	if (*line == '.')
		line++;

	len = strlen(line);

	/*
	 * If size of data overflows a size_t or exceeds max size allowed
	 * for a message, set permanent failure.
	 */
	if (SIZE_MAX - s->datalen < len + 1 ||
	    s->datalen + len + 1 > env->sc_maxsize) {
		s->msgflags |= MF_ERROR_SIZE;
		return;
	}
	s->datalen += len + 1;

	if (!(s->flags & SF_8BITMIME))
		for (i = 0; i < len; ++i)
			if (line[i] & 0x80)
				line[i] = line[i] & 0x7f;

	if (fprintf(s->ofile, "%s\n", line) != (int)len + 1) {
		log_warnx("warn: Error writing incoming message");
		s->msgflags |= MF_ERROR_IO;
	}
}

static void
smtp_message_end(struct smtp_session *s)
{
	struct queue_req_msg	req_queue;

	log_debug("debug: %p: end of message, msgflags=0x%04x", s, s->msgflags);

	tree_xpop(&wait_mfa_data, s->id);

	s->phase = PHASE_SETUP;

	if (!safe_fclose(s->ofile))
		s->msgflags |= MF_ERROR_IO;
	s->ofile = NULL;

	req_queue.reqid = s->id;
	req_queue.evpid = s->evp.id;

	if (s->msgflags & (MF_ERROR_SIZE | MF_ERROR_MFA)) {
		m_compose(p_queue, IMSG_QUEUE_REMOVE_MESSAGE, 0, 0, -1,
		    &req_queue, sizeof(req_queue));
		if (s->msgflags & MF_ERROR_SIZE)
			smtp_reply(s, "554 Message too big");
		else
			smtp_reply(s, "%i Message rejected", s->msgcode);
		smtp_message_reset(s, 0);
		smtp_enter_state(s, STATE_HELO);
		return;
	}

	if (s->msgflags & MF_ERROR_IO) {
		smtp_reply(s, "421 Temporary failure");
		smtp_enter_state(s, STATE_QUIT);
		return;
	}

	m_compose(p_queue, IMSG_QUEUE_COMMIT_MESSAGE, 0, 0, -1,
	    &req_queue, sizeof(req_queue));
	tree_xset(&wait_queue_commit, s->id, s);
}

static void
smtp_message_reset(struct smtp_session *s, int prepare)
{
	bzero(&s->evp, sizeof s->evp);
	s->msgflags = 0;
	s->destcount = 0;
	s->rcptcount = 0;
	s->datalen = 0;

	if (prepare) {
		s->evp.session_id = s->id;
		s->evp.ss = s->ss;
		strlcpy(s->evp.tag, s->listener->tag, sizeof(s->evp.tag));
		strlcpy(s->evp.hostname, s->hostname, sizeof s->evp.hostname);
		strlcpy(s->evp.helo, s->helo, sizeof s->evp.helo);

		if (s->flags & SF_BOUNCE)
			s->evp.flags |= EF_BOUNCE;
		if (s->flags & SF_AUTHENTICATED)
			s->evp.flags |= EF_AUTHENTICATED;
	}
}

static void
smtp_reply(struct smtp_session *s, char *fmt, ...)
{
	va_list	 ap;
	int	 n;
	char	 buf[SMTP_LINE_MAX], tmp[SMTP_LINE_MAX];

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	if (n == -1 || n >= SMTP_LINE_MAX)
		fatalx("smtp_reply: line too long");
	if (n < 4)
		fatalx("smtp_reply: response too short");

	log_trace(TRACE_SMTP, "smtp: %p: >>> %s", s, buf);

	iobuf_xfqueue(&s->iobuf, "smtp_reply", "%s\r\n", buf);

	switch (buf[0]) {
	case '5':
	case '4':
		strnvis(tmp, s->cmd, sizeof tmp, VIS_SAFE | VIS_CSTYLE);
		log_info("smtp-in: Failed command on session %016" PRIx64
		    ": \"%s\" => %.*s", s->id, tmp, n, buf);
		break;
	}
}

static void
smtp_query_mfa(struct smtp_session *s, int type, void *data, size_t len)
{
	m_compose(p_mfa, type, 0, 0, -1, data, len);
	s->mfa_imsg = type;
	tree_xset(&wait_mfa_response, s->id, s);	
}

static void
smtp_free(struct smtp_session *s, const char * reason)
{
	struct queue_req_msg	req_queue;
	struct mfa_req_msg	req_mfa;

	log_debug("debug: smtp: %p: deleting session: %s", s, reason);

	tree_pop(&wait_mfa_data, s->id);
	tree_pop(&wait_mfa_response, s->id);

	if (s->evp.id) {
		req_queue.reqid = s->id;
		req_queue.evpid = s->evp.id;
		m_compose(p_queue, IMSG_QUEUE_REMOVE_MESSAGE, 0, 0, -1,
		    &req_queue, sizeof(req_queue));
	}

	req_mfa.reqid = s->id;
	m_compose(p_mfa, IMSG_MFA_EVENT_DISCONNECT, 0, 0, -1,
	    &req_mfa, sizeof(req_mfa));

	if (s->ofile != NULL)
		fclose(s->ofile);

	if (s->flags & SF_SECURE && s->listener->flags & F_SMTPS)
		stat_decrement("smtp.smtps", 1);
	if (s->flags & SF_SECURE && s->listener->flags & F_STARTTLS)
		stat_decrement("smtp.tls", 1);

	io_clear(&s->io);
	iobuf_clear(&s->iobuf);
	free(s);

	smtp_collect();
}

static int
smtp_mailaddr(struct mailaddr *maddr, char *line, int mailfrom, char **args)
{
	char   *p, *e;

	if (*line != '<')
		return (0);

	e = strchr(line, '>');
	if (e == NULL)
		return (0);
	*e++ = '\0';
	while (*e == ' ')
		e++;
	*args = e;

	if (!email_to_mailaddr(maddr, line + 1))
		return (0);

	p = strchr(maddr->user, ':');
	if (p != NULL) {
		p++;
		memmove(maddr->user, p, strlen(p) + 1);
	}

	if (!valid_localpart(maddr->user) ||
	    !valid_localpart(maddr->domain)) {
		/* We accept empty sender for MAIL FROM */
		if (mailfrom &&
		    maddr->user[0] == '\0' &&
		    maddr->domain[0] == '\0')
			return (1);
		return (0);
	}

	return (1);
}

static int
smtp_verify_certificate(struct smtp_session *s)
{
	struct ca_vrfy_req_msg	req_ca_vrfy;
	struct iovec		iov[2];
	X509		       *x;
	STACK_OF(X509)	       *xchain;
	int			i;

	x = SSL_get_peer_certificate(s->io.ssl);
	if (x == NULL)
		return 0;
	xchain = SSL_get_peer_cert_chain(s->io.ssl);

	/*
	 * Client provided a certificate and possibly a certificate chain.
	 * SMTP can't verify because it does not have the information that
	 * it needs, instead it will pass the certificate and chain to the
	 * lookup process and wait for a reply.
	 *
	 */

	tree_xset(&wait_ssl_verify, s->id, s);

	/* Send the client certificate */
	bzero(&req_ca_vrfy, sizeof req_ca_vrfy);
	req_ca_vrfy.reqid = s->id;
	req_ca_vrfy.cert_len = i2d_X509(x, &req_ca_vrfy.cert);
	if (xchain)
		req_ca_vrfy.n_chain = sk_X509_num(xchain);
	iov[0].iov_base = &req_ca_vrfy;
	iov[0].iov_len = sizeof(req_ca_vrfy);
	iov[1].iov_base = req_ca_vrfy.cert;
	iov[1].iov_len = req_ca_vrfy.cert_len;
	m_composev(p_lka, IMSG_LKA_SSL_VERIFY_CERT, 0, 0, -1,
	    iov, nitems(iov));
	free(req_ca_vrfy.cert);

	if (xchain) {		
		/* Send the chain, one cert at a time */
		for (i = 0; i < sk_X509_num(xchain); ++i) {
			bzero(&req_ca_vrfy, sizeof req_ca_vrfy);
			req_ca_vrfy.reqid = s->id;
			x = sk_X509_value(xchain, i);
			req_ca_vrfy.cert_len = i2d_X509(x, &req_ca_vrfy.cert);
			iov[0].iov_base = &req_ca_vrfy;
			iov[0].iov_len  = sizeof(req_ca_vrfy);
			iov[1].iov_base = req_ca_vrfy.cert;
			iov[1].iov_len  = req_ca_vrfy.cert_len;
			m_composev(p_lka, IMSG_LKA_SSL_VERIFY_CHAIN, 0, 0, -1,
			    iov, nitems(iov));
			free(req_ca_vrfy.cert);
		}
	}

	/* Tell lookup process that it can start verifying, we're done */
	bzero(&req_ca_vrfy, sizeof req_ca_vrfy);
	req_ca_vrfy.reqid = s->id;
	m_compose(p_lka, IMSG_LKA_SSL_VERIFY, 0, 0, -1,
	    &req_ca_vrfy, sizeof req_ca_vrfy);

	return 1;
}

#define CASE(x) case x : return #x

const char *
smtp_strstate(int state)
{
	static char	buf[32];

	switch (state) {
	CASE(STATE_NEW);
	CASE(STATE_CONNECTED);
	CASE(STATE_TLS);
	CASE(STATE_HELO);
	CASE(STATE_AUTH_INIT);
	CASE(STATE_AUTH_USERNAME);
	CASE(STATE_AUTH_PASSWORD);
	CASE(STATE_AUTH_FINALIZE);
	CASE(STATE_BODY);
	CASE(STATE_QUIT);
	default:
		snprintf(buf, sizeof(buf), "STATE_??? (%d)", state);
		return (buf);
	}
}
