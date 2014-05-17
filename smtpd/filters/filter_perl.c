/*      $OpenBSD$   */

/*
 * Copyright (c) 2014 Gilles Chehade <gilles@poolp.org>
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

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include <EXTERN.h>
#include <XSUB.h>
#include <perl.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

static PerlInterpreter	*pi;
static CV		*pl_on_connect;
static CV		*pl_on_helo;
static CV		*pl_on_mail;
static CV		*pl_on_rcpt;
static CV		*pl_on_data;
static CV		*pl_on_eom;
static CV		*pl_on_commit;
static CV		*pl_on_rollback;
static CV		*pl_on_dataline;
static CV		*pl_on_disconnect;

XS(XS_filter_accept);
XS(XS_filter_reject);
XS(XS_filter_reject_code);
XS(XS_filter_writeln);

XS(XS_filter_accept)
{
	dXSARGS;
	uint64_t	id;
	int		ret;

	id = SvUV(ST(0));
	ret = filter_api_accept(id);
	XPUSHs(sv_2mortal(newSViv(ret)));
	XSRETURN(1);
}

XS(XS_filter_reject)
{
	dXSARGS;
	uint64_t	id;
	int		ret;

	id = SvUV(ST(0));
	ret = filter_api_reject(id, FILTER_CLOSE);
	XPUSHs(sv_2mortal(newSViv(ret)));
	XSRETURN(1);
}

XS(XS_filter_reject_code)
{
	dXSARGS;
	XSRETURN(1);
}

XS(XS_filter_writeln)
{
	dXSARGS;
	uint64_t	id;
	const char     *line;

	id   = SvUV(ST(0));
	line = SvPVX(ST(1));
	filter_api_writeln(id, line);
	XSRETURN(1);
}

void
call_sub_sv(SV *plsub, const char *format, ...)
{
	va_list ap;
	dSP;

	va_start(ap, format);

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);
	while (*format) {
		switch (*format++) {
		case 's':
			XPUSHs(sv_2mortal(newSVpv(va_arg(ap, char *), 0)));
			break;
		case 'i':
			XPUSHs(sv_2mortal(newSVuv(va_arg(ap, uint64_t))));
			break;
		}
	}
	PUTBACK;

	perl_call_sv(plsub, G_DISCARD);

	FREETMPS;
	LEAVE;

	va_end(ap);
}

static int
on_connect(uint64_t id, struct filter_connect *conn)
{
	const char *local;
	const char *remote;

	local = filter_api_sockaddr_to_text((struct sockaddr *)&conn->local);
	remote = filter_api_sockaddr_to_text((struct sockaddr *)&conn->remote);
	
	call_sub_sv((SV *)pl_on_connect, "%i%s%s%s", id, local, remote, conn->hostname);
}

static int
on_helo(uint64_t id, const char *helo)
{
	call_sub_sv((SV *)pl_on_helo, "%i%s", id, helo);
	return filter_api_accept(id);
}

static int
on_mail(uint64_t id, struct mailaddr *mail)
{
	const char *mailaddr;

	mailaddr = filter_api_mailaddr_to_text(mail);
	call_sub_sv((SV *)pl_on_mail, "%i%s", id, mailaddr);
	return filter_api_accept(id);
}

static int
on_rcpt(uint64_t id, struct mailaddr *rcpt)
{
	const char *mailaddr;

	mailaddr = filter_api_mailaddr_to_text(rcpt);
	call_sub_sv((SV *)pl_on_rcpt, "%i%s", id, mailaddr);
	return filter_api_accept(id);
}

static int
on_data(uint64_t id)
{
	call_sub_sv((SV *)pl_on_data, "%i", id);
	return filter_api_accept(id);
}

static int
on_eom(uint64_t id, size_t size)
{
	call_sub_sv((SV *)pl_on_eom, "%i", id);
	return filter_api_accept(id);
}

static void
on_commit(uint64_t id)
{
	call_sub_sv((SV *)pl_on_commit, "%i", id);
	return;
}

static void
on_rollback(uint64_t id)
{
	call_sub_sv((SV *)pl_on_rollback, "%i", id);
	return;
}

static void
on_disconnect(uint64_t id)
{
	call_sub_sv((SV *)pl_on_disconnect, "%i", id);
	return;
}

static void
on_dataline(uint64_t id, const char *line)
{
	call_sub_sv((SV *)pl_on_dataline, "%i%s", id, line);
}

int
main(int argc, char **argv)
{
	int	ch;
	char	*fake_argv[] = { "-e", "/tmp/test.pl", NULL };
	log_init(-1);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			log_warnx("warn: filter-perl: bad option");
			return (1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	pi = perl_alloc();
	perl_construct(pi);
	perl_parse(pi, NULL, argc, fake_argv, NULL);


	newXS("smtpd::filter_api_accept", XS_filter_accept, __FILE__);
	newXS("smtpd::filter_api_reject", XS_filter_reject, __FILE__);
	newXS("smtpd::filter_api_writeln", XS_filter_writeln, __FILE__);

	log_debug("debug: filter-perl: starting...");

	if ((pl_on_connect = perl_get_cv("on_connect", FALSE)))
		filter_api_on_connect(on_connect);
	if ((pl_on_helo = perl_get_cv("on_helo", FALSE)))
		filter_api_on_helo(on_helo);
	if ((pl_on_mail = perl_get_cv("on_mail", FALSE)))
		filter_api_on_mail(on_mail);
	if ((pl_on_rcpt = perl_get_cv("on_rcpt", FALSE)))
		filter_api_on_rcpt(on_rcpt);
	if ((pl_on_data = perl_get_cv("on_data", FALSE)))
		filter_api_on_data(on_data);
	if ((pl_on_eom = perl_get_cv("on_eom", FALSE)))
		filter_api_on_eom(on_eom);
	if ((pl_on_commit = perl_get_cv("on_commit", FALSE)))
		filter_api_on_commit(on_commit);
	if ((pl_on_rollback = perl_get_cv("on_rollback", FALSE)))
		filter_api_on_rollback(on_rollback);
	if ((pl_on_dataline = perl_get_cv("on_dataline", FALSE)))
		filter_api_on_dataline(on_dataline);
	if ((pl_on_disconnect = perl_get_cv("on_disconnect", FALSE)))
		filter_api_on_disconnect(on_disconnect);

	filter_api_loop();

	log_debug("debug: filter-perl: exiting");

	perl_destruct(pi);
	perl_free(pi);

	return (1);
}
