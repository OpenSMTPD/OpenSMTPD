/*
 * Copyright (c) 2001 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_UN_H
# include <sys/un.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h> /* for offsetof */

#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

//#include "ssh.h"
//#include "misc.h"
//#include "xmalloc.h"
//#include "atomicio.h"
//#include "pathnames.h"
#include "log.h"
//#include "buffer.h"

void
seed_rng(void)
{
	u_long	mask;
	int	error;

	/*
	 * OpenSSL version numbers: MNNFFPPS: major minor fix patch status
	 * We match major, minor, fix and status (not patch) for <1.0.0.
	 * After that, we acceptable compatible fix versions (so we
	 * allow 1.0.1 to work with 1.0.0). Going backwards is only allowed
	 * within a patch series.
	 */
	error = 0;
	mask = SSLeay() >= 0x1000000f ?  0xfff00000L : 0xfffff00fL;
	if (SSLeay() >= 0x1000000f)
		if ((SSLeay() & 0xfffffff0L) < (OPENSSL_VERSION_NUMBER & 0xfffffff0L))
			error = 1;
	if ((SSLeay() ^ OPENSSL_VERSION_NUMBER) & mask || (SSLeay() >> 12) < (OPENSSL_VERSION_NUMBER >> 12))
		error = 1;
	if (error)
		fatalx("OpenSSL version mismatch. Built against %lx, you have %lx\n",
		    (u_long)OPENSSL_VERSION_NUMBER, SSLeay());

	if (RAND_status() != 1)
		fatal("PRNG is not seeded");
}
