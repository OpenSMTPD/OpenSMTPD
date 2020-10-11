/*	$OpenBSD: mda_unpriv.c,v 1.6 2020/02/02 22:13:48 gilles Exp $	*/

/*
 * Copyright (c) 2018 Gilles Chehade <gilles@poolp.org>
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
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "smtpd.h"


void
mda_unpriv(struct dispatcher *dsp, struct deliver *deliver,
    const char *pw_name, const char *pw_dir)
{
	int		idx;
	char	       *mda_environ[11];
	char		mda_exec[LINE_MAX];
	char		mda_wrapper[LINE_MAX];
	const char     *mda_command;
	const char     *mda_command_wrap;

	if (deliver->mda_exec[0])
		mda_command = deliver->mda_exec;
	else
		mda_command = dsp->u.local.command;

	if (strlcpy(mda_exec, mda_command, sizeof (mda_exec))
	    >= sizeof (mda_exec))
		errx(1, "mda command line too long");

	if (mda_expand_format(mda_exec, sizeof mda_exec, deliver,
		&deliver->userinfo, NULL) == -1)
		errx(1, "mda command line could not be expanded");

	mda_command = mda_exec;

	/* setup environment similar to other MTA */
	idx = 0;
	xasprintf(&mda_environ[idx++], "PATH=%s", _PATH_DEFPATH);
	xasprintf(&mda_environ[idx++], "DOMAIN=%s", deliver->rcpt.domain);
	xasprintf(&mda_environ[idx++], "HOME=%s", pw_dir);
	xasprintf(&mda_environ[idx++], "RECIPIENT=%s@%s", deliver->dest.user, deliver->dest.domain);
	xasprintf(&mda_environ[idx++], "SHELL=/bin/sh");
	xasprintf(&mda_environ[idx++], "LOCAL=%s", deliver->rcpt.user);
	xasprintf(&mda_environ[idx++], "LOGNAME=%s", pw_name);
	xasprintf(&mda_environ[idx++], "USER=%s", pw_name);

	if (deliver->sender.user[0])
		xasprintf(&mda_environ[idx++], "SENDER=%s@%s",
		    deliver->sender.user, deliver->sender.domain);
	else
		xasprintf(&mda_environ[idx++], "SENDER=");

	if (deliver->mda_subaddress[0])
		xasprintf(&mda_environ[idx++], "EXTENSION=%s", deliver->mda_subaddress);

	mda_environ[idx++] = (char *)NULL;
	if (!deliver->mda_exec[0]) switch (dsp->u.local.type) {
	case DELIVER_MBOX:
	case DELIVER_INVALID:
	default:
		errx(EX_SOFTWARE, "internal bad delivery type (this is a bug)");
	case DELIVER_MAILDIR:
		execle(PATH_LIBEXEC"/mail.maildir", "mail.maildir", "--",
		    mda_command, NULL, mda_environ);
		goto bad;
	case DELIVER_MAILDIR_JUNK:
		execle(PATH_LIBEXEC"/mail.maildir", "mail.maildir", "-j", "--",
		    mda_command, NULL, mda_environ);
		goto bad;
	case DELIVER_LMTP:
		execle(PATH_LIBEXEC"/mail.lmtp", "mail.lmtp", "-d", mda_command,
		    "-u", NULL, mda_environ);
		goto bad;
	case DELIVER_LMTP_RCPT_TO:
		execle(PATH_LIBEXEC"/mail.lmtp", "mail.lmtp", "-d", mda_command,
		    "-r", NULL, mda_environ);
		goto bad;
	case DELIVER_MDA:
		execle(PATH_LIBEXEC"/mail.mda", "mail.mda", "--", mda_command,
		    NULL, mda_environ);
		goto bad;
	} else if (dsp->u.local.mda_wrapper) {
		mda_command_wrap = dict_get(env->sc_mda_wrappers,
		    dsp->u.local.mda_wrapper);
		if (mda_command_wrap == NULL)
			errx(1, "could not find wrapper %s",
			    dsp->u.local.mda_wrapper);

		if (strlcpy(mda_wrapper, mda_command_wrap, sizeof (mda_wrapper))
		    >= sizeof (mda_wrapper))
			errx(1, "mda command line too long");

		if (mda_expand_format(mda_wrapper, sizeof mda_wrapper, deliver,
			&deliver->userinfo, mda_command) == -1)
			errx(1, "mda command line could not be expanded");
		mda_command = mda_wrapper;
	}

	execle("/bin/sh", "/bin/sh", "-c", mda_command, (char *)NULL,
            mda_environ);

bad:
	perror("execle");
	_exit(1);
}

