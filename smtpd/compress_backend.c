/*	$OpenBSD: compress_backend.c,v 1.7 2013/01/26 09:37:23 gilles Exp $	*/

/*
 * Copyright (c) 2012 Charles Longeau <chl@openbsd.org>
 * Copyright (c) 2012 Gilles Chehade <gilles@poolp.org>
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
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd.h"

extern struct compress_backend compress_gzip;

struct compress_backend *
compress_backend_lookup(const char *name)
{
	if (!strcmp(name, "gzip"))
		return &compress_gzip;

	return NULL;
}

void *
compress_new(void)
{
	return (env->sc_comp->compress_new());
}

size_t
compress_chunk(void *hdl, void *ib, size_t ibsz, void *ob, size_t obsz)
{
	return (env->sc_comp->compress_chunk(hdl, ib, ibsz, ob, obsz));
}

void
compress_destroy(void *hdl)
{
	env->sc_comp->compress_destroy(hdl);
}

void *
uncompress_new(void)
{
	return (env->sc_comp->uncompress_new());
}

size_t
uncompress_chunk(void *hdl, void *ib, size_t ibsz, void *ob, size_t obsz)
{
	return (env->sc_comp->uncompress_chunk(hdl, ib, ibsz, ob, obsz));
}

void
uncompress_destroy(void *hdl)
{
	env->sc_comp->uncompress_destroy(hdl);
}

size_t
compress_buffer(char *ib, size_t iblen, char *ob, size_t oblen)
{
	return (compress_chunk(NULL, ib, iblen, ob, oblen));
}

size_t
uncompress_buffer(char *ib, size_t iblen, char *ob, size_t oblen)
{
	return (uncompress_chunk(NULL, ib, iblen, ob, oblen));
}

int
uncompress_file(FILE *ifile, FILE *ofile)
{
	return (0);
};
