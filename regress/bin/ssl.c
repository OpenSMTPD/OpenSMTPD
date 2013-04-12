/*	$OpenBSD: ssl.c,v 1.50 2012/11/12 14:58:53 eric Exp $	*/

/*
 * Copyright (c) 2008 Pierre-Yves Ritschard <pyr@openbsd.org>
 * Copyright (c) 2008 Reyk Floeter <reyk@openbsd.org>
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
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <ctype.h>
#include <err.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/err.h>

#define SSL_CIPHERS	"HIGH"

void	ssl_error(const char *);

static void	ssl_init(void);
static SSL_CTX *ssl_ctx_create(void);
static void    *ssl_client_ctx(void);

static void
ssl_init(void)
{
	static int	init = 0;

	if (init)
		return;

	init = 1;

	SSL_library_init();
	SSL_load_error_strings();

	OpenSSL_add_all_algorithms();

	/* Init hardware crypto engines. */
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();
}

void
ssl_error(const char *where)
{
	unsigned long	code;
	char		errbuf[128];

	for (; (code = ERR_get_error()) != 0 ;) {
		ERR_error_string_n(code, errbuf, sizeof(errbuf));
		fprintf(stderr, "debug: SSL library error: %s: %s",
		    where, errbuf);
	}
}

void *
ssl_connect(int sock)
{
	SSL	*ssl;

	ssl = ssl_client_ctx();

	if (SSL_set_fd(ssl, sock) == 0) {
		ssl_error("ssl_connect:SSL_set_fd");
		SSL_free(ssl);
		return (NULL);
	}

	if (SSL_connect(ssl) != 1) {
		ssl_error("ssl_connect:SSL_connect");
		SSL_free(ssl);
		return (NULL);
	}

	return ((void*)ssl);
}

void
ssl_close(void *a)
{
	SSL	*ssl = a;

	SSL_free(ssl);
}

static SSL_CTX *
ssl_ctx_create(void)
{
	SSL_CTX	*ctx;

	ssl_init();

	ctx = SSL_CTX_new(SSLv23_method());
	if (ctx == NULL) {
		ssl_error("ssl_ctx_create");
		errx(1, "ssl_ctx_create: could not create SSL context");
	}

	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_timeout(ctx, 30);
	SSL_CTX_set_options(ctx,
	    SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_TICKET);
	SSL_CTX_set_options(ctx,
	    SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

	if (!SSL_CTX_set_cipher_list(ctx, SSL_CIPHERS)) {
		ssl_error("ssl_ctx_create");
		errx(1, "ssl_ctx_create: could not set cipher list");
	}

	return (ctx);
}

static void *
ssl_client_ctx(void)
{
	SSL_CTX		*ctx;
	SSL		*ssl = NULL;
	int		 rv = -1;

	ctx = ssl_ctx_create();

	if ((ssl = SSL_new(ctx)) == NULL)
		goto done;
	SSL_CTX_free(ctx);

	if (!SSL_set_ssl_method(ssl, SSLv23_client_method()))
		goto done;

	rv = 0;
done:
	if (rv) {
		if (ssl)
			SSL_free(ssl);
		else if (ctx)
			SSL_CTX_free(ctx);
		ssl = NULL;
	}
	return (void*)(ssl);
}
