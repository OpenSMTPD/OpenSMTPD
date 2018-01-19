/*	$OpenBSD: ssl.h,v 1.20 2016/04/21 14:27:41 jsing Exp $	*/
/*
 * Copyright (c) 2013 Gilles Chehade <gilles@poolp.org>
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

#define SSL_CIPHERS		"HIGH:!aNULL:!MD5"
#define	SSL_SESSION_TIMEOUT	300

struct pki {
	char			 pki_name[HOST_NAME_MAX+1];

	char			*pki_cert_file;
	char			*pki_cert;
	off_t			 pki_cert_len;

	char			*pki_key_file;
	char			*pki_key;
	off_t			 pki_key_len;

	EVP_PKEY		*pki_pkey;

	int			 pki_dhe;
};

struct ca {
	char			 ca_name[HOST_NAME_MAX+1];

	char			*ca_cert_file;
	char			*ca_cert;
	off_t			 ca_cert_len;
};


/* ssl.c */
void		ssl_init(void);
int		ssl_setup(SSL_CTX **, struct pki *,
    int (*)(SSL *, int *, void *), const char *);
SSL_CTX	       *ssl_ctx_create(const char *, char *, off_t, const char *);
int	        ssl_cmp(struct pki *, struct pki *);
char	       *ssl_load_file(const char *, off_t *, mode_t);
char	       *ssl_load_key(const char *, off_t *, char *, mode_t, const char *);

const char     *ssl_to_text(const SSL *);
void		ssl_error(const char *);

int		ssl_load_certificate(struct pki *, const char *);
int		ssl_load_keyfile(struct pki *, const char *, const char *);
int		ssl_load_cafile(struct ca *, const char *);
int		ssl_load_pkey(const void *, size_t, char *, off_t,
		    X509 **, EVP_PKEY **);
int		ssl_ctx_fake_private_key(SSL_CTX *, const void *, size_t,
		    char *, off_t, X509 **, EVP_PKEY **);

/* ssl_privsep.c */
int		ssl_by_mem_ctrl(X509_LOOKUP *, int, const char *, long, char **);

#ifndef HAVE_SSL_CTX_SET_ECDH_AUTO
void	SSL_CTX_set_ecdh_auto(SSL_CTX *, int);
#endif
#ifndef HAVE_SSL_CTX_SET_DH_AUTO
void	SSL_CTX_set_dh_auto(SSL_CTX *, int);
#endif
int SSL_CTX_use_certificate_chain_mem(SSL_CTX *, void *, int);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)

static inline pem_password_cb *SSL_CTX_get_default_passwd_cb(SSL_CTX *ctx)
{
	return ctx->default_passwd_callback;
}

static inline void *SSL_CTX_get_default_passwd_cb_userdata(SSL_CTX *ctx)
{
	return ctx->default_passwd_callback_userdata;
}

#endif
