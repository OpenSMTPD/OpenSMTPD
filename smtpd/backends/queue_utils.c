/*	$OpenBSD: filter_api.c,v 1.4 2012/08/19 14:16:58 chl Exp $	*/

/*
 * Copyright (c) 2013 Eric Faurot <eric@openbsd.org>
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
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "queue_utils.h"
#include "log.h"

uint32_t
queue_generate_msgid(void)
{
	uint32_t msgid;

	while ((msgid = arc4random_uniform(0xffffffff)) == 0)
		;

	return msgid;
}

uint64_t
queue_generate_evpid(uint32_t msgid)
{
	uint32_t rnd;
	uint64_t evpid;

	while ((rnd = arc4random_uniform(0xffffffff)) == 0)
		;

	evpid = msgid;
	evpid <<= 32;
	evpid |= rnd;

	return evpid;
}

int
mktmpfile(const char *tempdir)
{
	char		path[SMTPD_MAXPATHLEN];
	int		fd;
	mode_t		omode;

	if (snprintf(path, sizeof(path), "%s/smtpd.XXXXXXXXXX", tempdir)
	    >= (int)sizeof(path)) {
		log_warnx("warn: queue-api: tempdir too large \"%s\"", tempdir);
		return (-1);
	}

	omode = umask(7077);
	if ((fd = mkstemp(path)) == -1) {
		log_warnx("warn: queue-api: cannot create temporary file \"%s\"",
		    path);
	}
	umask(omode);
	unlink(path);
	return (fd);
}
