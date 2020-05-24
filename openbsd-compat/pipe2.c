/*
 * Copyright (c) 2020 Gilles Chehade <gilles@poolp.org>
 * Copyright (C) 2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
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

#include <fcntl.h>
#include <unistd.h>

int
pipe2(int pipefd[2], int flags)
{
	if (pipe(pipefd) == -1)
		return -1;

	if ((flags & O_NONBLOCK) &&
	    (fcntl(pipefd[0], F_SETFL, O_NONBLOCK) == -1 ||
	     fcntl(pipefd[1], F_SETFL, O_NONBLOCK) == -1)) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}

	if ((flags & O_CLOEXEC) &&
	    (fcntl(pipefd[0], F_SETFD, FD_CLOEXEC) == -1 ||
	     fcntl(pipefd[1], F_SETFD, FD_CLOEXEC) == -1)) {
		close(pipefd[0]);
		close(pipefd[1]);
		return -1;
	}

	return 0;
}
