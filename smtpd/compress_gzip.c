/*	$OpenBSD: compress_gzip.c,v 1.6 2013/01/26 09:37:23 gilles Exp $	*/

/*
 * Copyright (c) 2012 Gilles Chehade <gilles@poolp.org>
 * Copyright (c) 2012 Charles Longeau <chl@openbsd.org>
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

#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <imsg.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <zlib.h>

#include "smtpd.h"
#include "log.h"

static void*	compress_gzip_new(void);
static size_t	compress_gzip_chunk(void *, void *, size_t, void *, size_t);
static void	compress_gzip_destroy(void *);
static void*	uncompress_gzip_new(void);
static size_t	uncompress_gzip_chunk(void *, void *, size_t, void *, size_t);
static void	uncompress_gzip_destroy(void *);

struct compress_backend	compress_gzip = {
	compress_gzip_new,
	compress_gzip_chunk,
	compress_gzip_destroy,

	uncompress_gzip_new,
	uncompress_gzip_chunk,
	uncompress_gzip_destroy
};

static void *
compress_gzip_new(void)
{
	z_stream	*strm;

	if ((strm = calloc(1, sizeof *strm)) == NULL)
		return NULL;
	
	strm->zalloc = Z_NULL;
	strm->zfree = Z_NULL;
	strm->opaque = Z_NULL;
	if (deflateInit2(strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
		(15+16), 8, Z_DEFAULT_STRATEGY) != Z_OK)
		goto error;

	return strm;

error:
	free(strm);
	return NULL;
}

static size_t
compress_gzip_chunk(void *hdl, void *ib, size_t ibsz, void *ob, size_t obsz)
{
	z_stream	*strm = hdl;

	strm->avail_in  = ibsz;
	strm->next_in   = (unsigned char *)ib;
	strm->avail_out = obsz;
	strm->next_out  = (unsigned char *)ob;

	if (deflate(strm, Z_FINISH) != Z_STREAM_END)
		return 0;

	return strm->total_out;
}

static void
compress_gzip_destroy(void *hdl)
{
	deflateEnd(hdl);
}

static void *
uncompress_gzip_new(void)
{
	z_stream	*strm;

	if ((strm = calloc(1, sizeof *strm)) == NULL)
		return NULL;

	strm->zalloc   = Z_NULL;
	strm->zfree    = Z_NULL;
	strm->opaque   = Z_NULL;
	strm->avail_in = 0;
	strm->next_in  = Z_NULL;

	if (inflateInit2(strm, (15+16)) != Z_OK)
		goto error;

	return strm;

error:
	free(strm);
	return NULL;
}

static size_t
uncompress_gzip_chunk(void *hdl, void *ib, size_t ibsz, void *ob, size_t obsz)
{
	z_stream	*strm = hdl;

	strm->avail_in  = ibsz;
	strm->next_in   = (unsigned char *)ib;
	strm->avail_out = obsz;
	strm->next_out  = (unsigned char *)ob;

	if (inflate(strm, Z_FINISH) != Z_STREAM_END)
		return 0;

	return strm->total_out;
}

static void
uncompress_gzip_destroy(void *hdl)
{
	inflateEnd(hdl);
}
