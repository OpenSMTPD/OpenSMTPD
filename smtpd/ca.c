/*	$OpenBSD: ca.c,v 1.28 2017/11/21 12:20:34 eric Exp $	*/

/*
 * Copyright (c) 2014 Reyk Floeter <reyk@openbsd.org>
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

#include "includes.h"

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/tree.h>

#include <grp.h> /* needed for setgroups */
#include <err.h>
#include <imsg.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/err.h>

#include "smtpd.h"
#include "log.h"
#include "ssl.h"

static int	 ca_verify_cb(int, X509_STORE_CTX *);

static int	 rsae_send_imsg(int, const unsigned char *, unsigned char *,
		    RSA *, int, unsigned int);
static int	 rsae_pub_enc(int, const unsigned char *, unsigned char *,
		    RSA *, int);
static int	 rsae_pub_dec(int,const unsigned char *, unsigned char *,
		    RSA *, int);
static int	 rsae_priv_enc(int, const unsigned char *, unsigned char *,
		    RSA *, int);
static int	 rsae_priv_dec(int, const unsigned char *, unsigned char *,
		    RSA *, int);
static int	 rsae_mod_exp(BIGNUM *, const BIGNUM *, RSA *, BN_CTX *);
static int	 rsae_bn_mod_exp(BIGNUM *, const BIGNUM *, const BIGNUM *,
		    const BIGNUM *, BN_CTX *, BN_MONT_CTX *);
static int	 rsae_init(RSA *);
static int	 rsae_finish(RSA *);
static int	 rsae_keygen(RSA *, int, BIGNUM *, BN_GENCB *);

static uint64_t	 rsae_reqid = 0;

static void
ca_shutdown(void)
{
	log_debug("debug: ca agent exiting");
	_exit(0);
}

int
ca(void)
{
	struct passwd	*pw;

	purge_config(PURGE_LISTENERS|PURGE_TABLES|PURGE_RULES);

	if ((pw = getpwnam(SMTPD_USER)) == NULL)
		fatalx("unknown user " SMTPD_USER);

	if (chroot(PATH_CHROOT) == -1)
		fatal("ca: chroot");
	if (chdir("/") == -1)
		fatal("ca: chdir(\"/\")");

	config_process(PROC_CA);

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("ca: cannot drop privileges");

	imsg_callback = ca_imsg;
	event_init();

	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	config_peer(PROC_CONTROL);
	config_peer(PROC_PARENT);
	config_peer(PROC_PONY);

	/* Ignore them until we get our config */
	mproc_disable(p_pony);

	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	event_dispatch();
	fatalx("exited event loop");

	return (0);
}

void
ca_init(void)
{
	BIO		*in = NULL;
	EVP_PKEY	*pkey = NULL;
	struct pki	*pki;
	const char	*k;
	void		*iter_dict;

	log_debug("debug: init private ssl-tree");
	iter_dict = NULL;
	while (dict_iter(env->sc_pki_dict, &iter_dict, &k, (void **)&pki)) {
		if (pki->pki_key == NULL)
			continue;

		if ((in = BIO_new_mem_buf(pki->pki_key,
		    pki->pki_key_len)) == NULL)
			fatalx("ca_launch: key");

		if ((pkey = PEM_read_bio_PrivateKey(in,
		    NULL, NULL, NULL)) == NULL)
			fatalx("ca_launch: PEM");
		BIO_free(in);

		pki->pki_pkey = pkey;

		freezero(pki->pki_key, pki->pki_key_len);
		pki->pki_key = NULL;
	}
}

static int
ca_verify_cb(int ok, X509_STORE_CTX *ctx)
{
	switch (X509_STORE_CTX_get_error(ctx)) {
	case X509_V_OK:
		break;
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		break;
        case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		break;
        case X509_V_ERR_CERT_HAS_EXPIRED:
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		break;
        case X509_V_ERR_NO_EXPLICIT_POLICY:
		break;
	}
	return ok;
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)

static int RSA_meth_get_flags(RSA_METHOD *meth)
{
	return meth->flags;
}

static int RSA_meth_set_flags(RSA_METHOD *meth, int flags)
{
	meth->flags = flags;
	return 1;
}

static void *RSA_meth_get0_app_data(const RSA_METHOD *meth)
{
	return meth->app_data;
}

static int RSA_meth_set0_app_data(RSA_METHOD *meth, void *app_data)
{
	meth->app_data = app_data;
	return 1;
}

static int (*RSA_meth_get_pub_enc(const RSA_METHOD *meth))
(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	return meth->rsa_pub_enc;
}

static int RSA_meth_set_pub_enc(RSA_METHOD *meth,
	int (*pub_enc) (int flen, const unsigned char *from,
			unsigned char *to, RSA *rsa,
			int padding))
{
	meth->rsa_pub_enc = pub_enc;
	return 1;
}

static int (*RSA_meth_get_pub_dec(const RSA_METHOD *meth))
(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	return meth->rsa_pub_dec;
}

static int (*RSA_meth_get_priv_enc(const RSA_METHOD *meth))
(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	return meth->rsa_priv_enc;
}

int RSA_meth_set_priv_enc(RSA_METHOD *meth,
  int (*priv_enc) (int flen, const unsigned char *from,
  unsigned char *to, RSA *rsa, int padding))
{
	meth->rsa_priv_enc = priv_enc;
	return 1;
}

static int (*RSA_meth_get_priv_dec(const RSA_METHOD *meth))
(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
	return meth->rsa_priv_dec;
}

static int RSA_meth_set_priv_dec(RSA_METHOD *meth,
  int (*priv_dec) (int flen, const unsigned char *from,
  unsigned char *to, RSA *rsa, int padding))
{
	meth->rsa_priv_dec = priv_dec;
	return 1;
}

static int (*RSA_meth_get_mod_exp(const RSA_METHOD *meth))
  (BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
	return meth->rsa_mod_exp;
}

static int RSA_meth_set_mod_exp(RSA_METHOD *meth,
  int (*mod_exp) (BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx))
{
	meth->rsa_mod_exp = mod_exp;
	return 1;
}

static int (*RSA_meth_get_bn_mod_exp(const RSA_METHOD *meth))
(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
	return meth->bn_mod_exp;
}

static int RSA_meth_set_bn_mod_exp(RSA_METHOD *meth, int (*bn_mod_exp)
  (BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
   BN_CTX *ctx, BN_MONT_CTX *m_ctx))
{
	meth->bn_mod_exp = bn_mod_exp;
	return 1;
}

static int (*RSA_meth_get_init(const RSA_METHOD *meth)) (RSA *rsa)
{
	return meth->init;
}

static int RSA_meth_set_init(RSA_METHOD *meth, int (*init) (RSA *rsa))
{
	meth->init = init;
	return 1;
}

static int (*RSA_meth_get_finish(const RSA_METHOD *meth)) (RSA *rsa)
{
	return meth->finish;
}

static int RSA_meth_set_finish(RSA_METHOD *meth, int (*finish) (RSA *rsa))
{
	meth->finish = finish;
	return 1;
}

static int (*RSA_meth_get_keygen(const RSA_METHOD *meth))
  (RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
	return meth->rsa_keygen;
}

static int RSA_meth_set_keygen(RSA_METHOD *meth, int (*keygen)
  (RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb))
{
	meth->rsa_keygen = keygen;
	return 1;
}

static int (*RSA_meth_get_verify(const RSA_METHOD *meth))
  (int dtype, const unsigned char *m,
   unsigned int m_length, const unsigned char *sigbuf,
   unsigned int siglen, const RSA *rsa)
{
	if (meth->flags & RSA_FLAG_SIGN_VER)
		return meth->rsa_verify;
	return NULL;
}

static int (*RSA_meth_get_sign(const RSA_METHOD *meth))
  (int type,
   const unsigned char *m, unsigned int m_length,
   unsigned char *sigret, unsigned int *siglen,
   const RSA *rsa)
{
	if (meth->flags & RSA_FLAG_SIGN_VER)
		return meth->rsa_sign;
	return NULL;
}

static int RSA_meth_set_pub_dec(RSA_METHOD *meth,
 int (*pub_dec) (int flen, const unsigned char *from,
   unsigned char *to, RSA *rsa, int padding))
{
	meth->rsa_pub_dec = pub_dec;
	return 1;
}

static RSA_METHOD *RSA_meth_new(const char *name, int flags)
{
	RSA_METHOD *meth = malloc(sizeof(*meth));

	if (meth != NULL) {
		memset(meth, 0, sizeof(*meth));
		meth->flags = flags;

		meth->name = strdup(name);
		if (meth->name != NULL)
			return meth;

		free(meth);
	}

	return NULL;
}

#endif

int
ca_X509_verify(void *certificate, void *chain, const char *CAfile,
    const char *CRLfile, const char **errstr)
{
	X509_STORE     *store = NULL;
	X509_STORE_CTX *xsc = NULL;
	int		ret = 0;

	if ((store = X509_STORE_new()) == NULL)
		goto end;

	if (!X509_STORE_load_locations(store, CAfile, NULL)) {
		log_warn("warn: unable to load CA file %s", CAfile);
		goto end;
	}
	X509_STORE_set_default_paths(store);

	if ((xsc = X509_STORE_CTX_new()) == NULL)
		goto end;

	if (X509_STORE_CTX_init(xsc, store, certificate, chain) != 1)
		goto end;

	X509_STORE_CTX_set_verify_cb(xsc, ca_verify_cb);

	ret = X509_verify_cert(xsc);

end:
	*errstr = NULL;
	if (ret != 1) {
		if (xsc)
			*errstr = X509_verify_cert_error_string(X509_STORE_CTX_get_error(xsc));
		else if (ERR_peek_last_error())
			*errstr = ERR_error_string(ERR_peek_last_error(), NULL);
	}

	X509_STORE_CTX_free(xsc);
	X509_STORE_free(store);

	return ret > 0 ? 1 : 0;
}

void
ca_imsg(struct mproc *p, struct imsg *imsg)
{
	RSA			*rsa;
	const void		*from = NULL;
	unsigned char		*to = NULL;
	struct msg		 m;
	const char		*pkiname;
	size_t			 flen, tlen, padding;
	struct pki		*pki;
	int			 ret = 0;
	uint64_t		 id;
	int			 v;

	if (imsg == NULL)
		ca_shutdown();

	switch (imsg->hdr.type) {
	case IMSG_CONF_START:
		return;
	case IMSG_CONF_END:
		ca_init();

		/* Start fulfilling requests */
		mproc_enable(p_pony);
		return;

	case IMSG_CTL_VERBOSE:
		m_msg(&m, imsg);
		m_get_int(&m, &v);
		m_end(&m);
		log_trace_verbose(v);
		return;

	case IMSG_CTL_PROFILE:
		m_msg(&m, imsg);
		m_get_int(&m, &v);
		m_end(&m);
		profiling = v;
		return;

	case IMSG_CA_PRIVENC:
	case IMSG_CA_PRIVDEC:
		m_msg(&m, imsg);
		m_get_id(&m, &id);
		m_get_string(&m, &pkiname);
		m_get_data(&m, &from, &flen);
		m_get_size(&m, &tlen);
		m_get_size(&m, &padding);
		m_end(&m);

		pki = dict_get(env->sc_pki_dict, pkiname);
		if (pki == NULL || pki->pki_pkey == NULL ||
		    (rsa = EVP_PKEY_get1_RSA(pki->pki_pkey)) == NULL)
			fatalx("ca_imsg: invalid pki");

		if ((to = calloc(1, tlen)) == NULL)
			fatalx("ca_imsg: calloc");

		switch (imsg->hdr.type) {
		case IMSG_CA_PRIVENC:
			ret = RSA_private_encrypt(flen, from, to, rsa,
			    padding);
			break;
		case IMSG_CA_PRIVDEC:
			ret = RSA_private_decrypt(flen, from, to, rsa,
			    padding);
			break;
		}

		m_create(p, imsg->hdr.type, 0, 0, -1);
		m_add_id(p, id);
		m_add_int(p, ret);
		if (ret > 0)
			m_add_data(p, to, (size_t)ret);
		m_close(p);

		free(to);
		RSA_free(rsa);

		return;
	}

	errx(1, "ca_imsg: unexpected %s imsg", imsg_to_str(imsg->hdr.type));
}

/*
 * RSA privsep engine (called from unprivileged processes)
 */

static const RSA_METHOD *rsa_default = NULL;

static const char *rsae_method_name = "RSA privsep engine";

static int
rsae_send_imsg(int flen, const unsigned char *from, unsigned char *to,
    RSA *rsa, int padding, unsigned int cmd)
{
	int		 ret = 0;
	struct imsgbuf	*ibuf;
	struct imsg	 imsg;
	int		 n, done = 0;
	const void	*toptr;
	char		*pkiname;
	size_t		 tlen;
	struct msg	 m;
	uint64_t	 id;

	if ((pkiname = RSA_get_ex_data(rsa, 0)) == NULL)
		return (0);

	/*
	 * Send a synchronous imsg because we cannot defer the RSA
	 * operation in OpenSSL's engine layer.
	 */
	m_create(p_ca, cmd, 0, 0, -1);
	rsae_reqid++;
	m_add_id(p_ca, rsae_reqid);
	m_add_string(p_ca, pkiname);
	m_add_data(p_ca, (const void *)from, (size_t)flen);
	m_add_size(p_ca, (size_t)RSA_size(rsa));
	m_add_size(p_ca, (size_t)padding);
	m_flush(p_ca);

	ibuf = &p_ca->imsgbuf;

	while (!done) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatalx("imsg_read");
		if (n == 0)
			fatalx("pipe closed");

		while (!done) {
			if ((n = imsg_get(ibuf, &imsg)) == -1)
				fatalx("imsg_get error");
			if (n == 0)
				break;

			log_imsg(PROC_PONY, PROC_CA, &imsg);

			switch (imsg.hdr.type) {
			case IMSG_CA_PRIVENC:
			case IMSG_CA_PRIVDEC:
				break;
			default:
				/* Another imsg is queued up in the buffer */
				pony_imsg(p_ca, &imsg);
				imsg_free(&imsg);
				continue;
			}

			m_msg(&m, &imsg);
			m_get_id(&m, &id);
			if (id != rsae_reqid)
				fatalx("invalid response id");
			m_get_int(&m, &ret);
			if (ret > 0)
				m_get_data(&m, &toptr, &tlen);
			m_end(&m);

			if (ret > 0)
				memcpy(to, toptr, tlen);
			done = 1;

			imsg_free(&imsg);
		}
	}
	mproc_event_add(p_ca);

	return (ret);
}

static int
rsae_pub_enc(int flen,const unsigned char *from, unsigned char *to, RSA *rsa,
    int padding)
{
	log_debug("debug: %s: %s", proc_name(smtpd_process), __func__);
	return (RSA_meth_get_pub_enc(rsa_default)(flen, from, to, rsa, padding));
}

static int
rsae_pub_dec(int flen,const unsigned char *from, unsigned char *to, RSA *rsa,
    int padding)
{
	log_debug("debug: %s: %s", proc_name(smtpd_process), __func__);
	return (RSA_meth_get_pub_dec(rsa_default)(flen, from, to, rsa, padding));
}

static int
rsae_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,
    int padding)
{
	log_debug("debug: %s: %s", proc_name(smtpd_process), __func__);
	if (RSA_get_ex_data(rsa, 0) != NULL) {
		return (rsae_send_imsg(flen, from, to, rsa, padding,
		    IMSG_CA_PRIVENC));
	}
	return (RSA_meth_get_priv_enc(rsa_default)(flen, from, to, rsa, padding));
}

static int
rsae_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa,
    int padding)
{
	log_debug("debug: %s: %s", proc_name(smtpd_process), __func__);
	if (RSA_get_ex_data(rsa, 0) != NULL) {
		return (rsae_send_imsg(flen, from, to, rsa, padding,
		    IMSG_CA_PRIVDEC));
	}
	return (RSA_meth_get_priv_dec(rsa_default)(flen, from, to, rsa, padding));
}

static int
rsae_mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx)
{
	log_debug("debug: %s: %s", proc_name(smtpd_process), __func__);
	return (RSA_meth_get_mod_exp(rsa_default)(r0, I, rsa, ctx));
}

static int
rsae_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx)
{
	log_debug("debug: %s: %s", proc_name(smtpd_process), __func__);
	return (RSA_meth_get_bn_mod_exp(rsa_default)(r, a, p, m, ctx, m_ctx));
}

static int
rsae_init(RSA *rsa)
{
	log_debug("debug: %s: %s", proc_name(smtpd_process), __func__);
	if (RSA_meth_get_init(rsa_default) == NULL)
		return (1);
	return (RSA_meth_get_init(rsa_default)(rsa));
}

static int
rsae_finish(RSA *rsa)
{
	log_debug("debug: %s: %s", proc_name(smtpd_process), __func__);
	if (RSA_meth_get_finish(rsa_default) == NULL)
		return (1);
	return (RSA_meth_get_finish(rsa_default)(rsa));
}

static int
rsae_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
	log_debug("debug: %s: %s", proc_name(smtpd_process), __func__);
	return (RSA_meth_get_keygen(rsa_default)(rsa, bits, e, cb));
}

static RSA_METHOD *rsae_method;

void
ca_engine_init(void)
{
	ENGINE		*e;
	const char	*errstr, *name;

	if ((e = ENGINE_get_default_RSA()) == NULL) {
		if ((e = ENGINE_new()) == NULL) {
			errstr = "ENGINE_new";
			goto fail;
		}
		if (!ENGINE_set_name(e, rsae_method_name)) {
			errstr = "ENGINE_set_name";
			goto fail;
		}
		if ((rsa_default = RSA_get_default_method()) == NULL) {
			errstr = "RSA_get_default_method";
			goto fail;
		}
	} else if ((rsa_default = ENGINE_get_RSA(e)) == NULL) {
		errstr = "ENGINE_get_RSA";
		goto fail;
	}

	rsae_method = RSA_meth_new(rsae_method_name, 0);
	if (!rsae_method) {
		errstr = "RSA_meth_new";
		goto fail;
	}

	if ((name = ENGINE_get_name(e)) == NULL)
		name = "unknown RSA engine";

	log_debug("debug: %s: using %s", __func__, name);

	if (RSA_meth_get_sign(rsa_default) ||
	    RSA_meth_get_verify(rsa_default))
		fatalx("unsupported RSA engine");

	errstr = "Setting callback";
	if (!RSA_meth_set_pub_enc(rsae_method, rsae_pub_enc))
		goto fail;
        if (!RSA_meth_set_pub_dec(rsae_method, rsae_pub_dec))
		goto fail;
        if (!RSA_meth_set_priv_enc(rsae_method, rsae_priv_enc))
		goto fail;
        if (!RSA_meth_set_priv_dec(rsae_method, rsae_priv_dec))
		goto fail;

	if (RSA_meth_get_mod_exp(rsa_default)) {
		if (!RSA_meth_set_mod_exp(rsae_method, rsae_mod_exp))
			goto fail;
	}

	if (RSA_meth_get_bn_mod_exp(rsa_default))
		if (!RSA_meth_set_bn_mod_exp(rsae_method, rsae_bn_mod_exp))
			goto fail;
        if (!RSA_meth_set_init(rsae_method, rsae_init))
		goto fail;
        if (!RSA_meth_set_finish(rsae_method, rsae_finish))
		goto fail;

	if (RSA_meth_get_keygen(rsa_default)) {
		if (!RSA_meth_set_keygen(rsae_method, rsae_keygen))
			goto fail;
	}

	if (!RSA_meth_set_flags(rsae_method,
			   RSA_meth_get_flags(rsa_default) |
			   RSA_METHOD_FLAG_NO_CHECK))
		goto fail;

	if (!RSA_meth_set0_app_data(rsae_method, RSA_meth_get0_app_data(rsa_default)))
		goto fail;

	if (!ENGINE_set_RSA(e, rsae_method)) {
		errstr = "ENGINE_set_RSA";
		goto fail;
	}
	if (!ENGINE_set_default_RSA(e)) {
		errstr = "ENGINE_set_default_RSA";
		goto fail;
	}

	return;

 fail:
	ssl_error(errstr);
	fatalx("%s", errstr);
}
