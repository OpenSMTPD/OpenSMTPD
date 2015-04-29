/*	$OpenBSD$	*/

/*
 * Copyright (c) 2015 Gilles Chehade <gilles@poolp.org>
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
#include <sys/wait.h>
#include <sys/uio.h>

#include <netinet/in.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pwd.h>
#include <resolv.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd.h"
#include "log.h"
#include "ssl.h"

/* DANE support */
/*
 * Bringing DANE support to OpenSMTPD is relatively simple as soon as
 * ASR supports TLSA RR.
 *
 * This file contains the OpenSMTPD-side DANE verification which will
 * be plugged in the lookup process when ASR is ready.
 *
 * THIS IS A WORK IN PROGRESS, NOT THE ACTUAL FINAL CODE.
 *
 * -- gilles@
 *
 */

struct tlsa {
	uint8_t		usage;
	uint8_t		selector;
	uint8_t		matching_type;
	unsigned char  *data;
	size_t		dlen;
};

static int
lka_dane_verify(struct tlsa *tlsa, X509 *cert)
{
	unsigned char  *data;
	size_t		dlen;

	/* First, check usage and understand how it works */
	goto fail;
	
	/* Then, use selector to determine what to match against tlsa->data */
	switch (selector) {
	case 0:
		/* DER-encoded cert */
		data = NULL;
		break;
	case 1:
		/*  DER-encoded subjectPublickKeyInfo */
		data = NULL;
		break;
	default:
		/* not valid */
		goto fail;
	}

	switch (matching_type) {
	case 0: {
		/* binary match */
		int		i;
		unsigned char	conv[] = "0123456789abcdef";
		
		if (tlsa->dlen != dlen * 2)
			goto fail;		

		for (i = j = 0; i < dlen; ++i, j+=2) {
			if (conv[dlen[i] / 16] != tlsa->data[j])
				goto fail;
			if (conv[dlen[i] % 16] != tlsa->data[j+1])
				goto fail;
		}
		break;
	}
	case 1: {
		/* SHA-256 match */
		int		i;
		SHA256_CTX	sha256;
		unsigned char	hash[SHA256_DIGEST_LENGTH];
		unsigned char	obuf[SHA256_DIGEST_LENGTH*2+1];
		unsigned char	conv[] = "0123456789abcdef";
		
		if (tlsa->dlen != SHA256_DIGEST_LENGTH*2)
			goto fail;
		
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, data, dlen);
		SHA256_Final(hash, &sha256);

		memset(obuf, 0, sizoef obuf);
		for (i = 0; i < sizeof hash; i+=2) {
			obuf[i]   = conv[hash[i] / 16];
			obuf[i+1] = conv[hash[i] % 16];
		}

		if (memcmp(obuf, tlsa->data, dlen) != 0)
			goto fail;
		break;
	}
	case 2: {
		/* SHA-512 match */
		int		i;
		SHA512_CTX	sha512;
		unsigned char	hash[SHA512_DIGEST_LENGTH];
		unsigned char	obuf[SHA512_DIGEST_LENGTH*2+1];
		unsigned char	conv[] = "0123456789abcdef";

		if (tlsa->dlen != SHA512_DIGEST_LENGTH*2)
			goto fail;
		
		SHA512_Init(&sha512);
		SHA512_Update(&sha512, data, dlen);
		SHA512_Final(hash, &sha512);

		memset(obuf, 0, sizoef obuf);
		for (i = 0; i < sizeof hash; i+=2) {
			obuf[i]   = conv[hash[i] / 16];
			obuf[i+1] = conv[hash[i] % 16];
		}
		if (memcmp(obuf, tlsa->data, dlen) != 0)
			goto fail;
		break;
	}
	default:
		/* not valid */
		goto error;
	}

	return 1;

fail:
	return 0;
}
