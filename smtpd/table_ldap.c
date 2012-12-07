/*
 * Copyright (c) 2010-2012 Gilles Chehade <gilles@openbsd.org>
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

#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtpd.h"
#include "aldap.h"
#include "log.h"

#define MAX_LDAP_IDENTIFIER		 32
#define MAX_LDAP_URL		 	 256
#define MAX_LDAP_USERNAME      	 256
#define MAX_LDAP_PASSWORD      	 256
#define MAX_LDAP_BASELEN      	 128
#define MAX_LDAP_FILTERLEN     	 1024
#define MAX_LDAP_FIELDLEN      	 128

static void			*table_ldap_open(struct table *);
static int			 table_ldap_update(struct table *);
static int			 table_ldap_config(struct table *, const char *);
static int			 table_ldap_lookup(void *, const  char *, enum table_service, void **);
static void			 table_ldap_close(void *);
static struct aldap		*ldap_client_connect(const char *);

struct table_backend table_backend_ldap = {
	K_CREDENTIALS|K_USERINFO,
	table_ldap_config,
	table_ldap_open,
	table_ldap_update,
	table_ldap_close,
	table_ldap_lookup
};

struct table_ldap_handle {
	struct aldap	*aldap;
	struct table	*table;
};

static int	parse_attributes(char ***, const char *, size_t);

static int	table_ldap_credentials(struct table_ldap_handle *, const char *, void **);
static int	table_ldap_userinfo(struct table_ldap_handle *, const char *, void **);


static int
table_ldap_config(struct table *table, const char *config)
{
	void	*cfg = NULL;

	/* no config ? broken */
	if (config == NULL)
		return 0;

	cfg = table_config_create();
	if (! table_config_parse(cfg, config, T_HASH))
		goto err;

	/* sanity checks */
	if (table_config_get(cfg, "url") == NULL) {
		log_warnx("table_ldap: missing 'url' configuration");
		goto err;
	}

	if (table_config_get(cfg, "basedn") == NULL) {
		log_warnx("table_ldap: missing 'basedn' configuration");
		goto err;
	}

	table_set_configuration(table, cfg);
	return 1;

err:
	table_destroy(cfg);
	return 0;

}

static int
table_ldap_update(struct table *table)
{
	return 1;
}

static void *
table_ldap_open(struct table *table)
{
	struct table			*cfg = NULL;
	struct table_ldap_handle	*tlh = NULL;
	struct aldap_message		*message = NULL;
	char				*url;
	char				*basedn;
	char				*username;
	char				*password;


	cfg      = table_get_configuration(table);
	url      = table_get(cfg, "url");
	username = table_get(cfg, "username");
	password = table_get(cfg, "password");

	if (url == NULL || username == NULL || password == NULL)
		goto err;

	url      = xstrdup(url, "table_ldap_open");
	username = xstrdup(username, "table_ldap_open");
	password = xstrdup(password, "table_ldap_open");

	tlh = xcalloc(1, sizeof(*tlh), "table_ldap_open");
	tlh->table = table;
	tlh->aldap = ldap_client_connect(url);
	if (tlh->aldap == NULL) {
		log_warnx("table_ldap_open: ldap_client_connect error");
		goto err;
	}

	if (aldap_bind(tlh->aldap, username, password) == -1) {
		log_warnx("table_ldap_open: aldap_bind error");
		goto err;
	}

	if ((message = aldap_parse(tlh->aldap)) == NULL) {
		log_warnx("table_ldap_open: aldap_parse");
		goto err;
	}

	switch (aldap_get_resultcode(message)) {
	case LDAP_SUCCESS:
		log_warnx("table_ldap_open: ldap server accepted credentials");
		break;
	case LDAP_INVALID_CREDENTIALS:
		log_warnx("table_ldap_open: ldap server refused credentials");
		goto err;
	default:
		log_warnx("table_ldap_open: failed to bind, result #%d", aldap_get_resultcode(message));
		goto err;
	}

	return tlh;

err:
	if (tlh->aldap != NULL)
		aldap_close(tlh->aldap);
	free(tlh);
	if (message != NULL)
		aldap_freemsg(message);
	return NULL;
}

static void
table_ldap_close(void *hdl)
{
	struct table_ldap_handle	*tlh = hdl;

	aldap_close(tlh->aldap);
	free(tlh);
}

static int
table_ldap_lookup(void *hdl, const char *key, enum table_service service,
		void **retp)
{
	struct table_ldap_handle	*tlh = hdl;

	switch (service) {
#if 0
	case K_ALIAS:
		return table_ldap_alias(tlh, key, retp);
#endif
	case K_CREDENTIALS:
		return table_ldap_credentials(tlh, key, retp);

	case K_USERINFO:
		return table_ldap_userinfo(tlh, key, retp);

	default:
		break;
	}

	return 0;
}

static int
filter_expand(char **expfilter, const char *filter, const char *key)
{
	if (asprintf(expfilter, filter, key) < 0)
		return 0;
	return 1;
}

static int
ldap_query_single_entry(struct aldap *aldap, const char *basedn,
    const char *filter, char **attributes, char **outp)
{
	struct aldap_message   *m = NULL;
	char		      **ldapattrsp;
	int			ret;
	int			i;

	ret = aldap_search(aldap, basedn, LDAP_SCOPE_SUBTREE, filter, NULL,
	    0, 0, 0, NULL);
	if (ret == -1)
		return -1;

	ret = 0;
	while ((m = aldap_parse(aldap)) != NULL) {
		if (aldap->msgid != m->msgid)
			goto error;
		if (m->message_type == LDAP_RES_SEARCH_RESULT)
			break;
		if (m->message_type != LDAP_RES_SEARCH_ENTRY)
			goto error;
		ret = 1;
		for (i = 0; attributes[i]; ++i) {
			if (aldap_match_attr(m, attributes[i], &ldapattrsp) != 1)
				goto error;	
			outp[i] = xstrdup(ldapattrsp[0], "ldap_query_single_entry");
			aldap_free_attr(ldapattrsp);
			ldapattrsp = NULL;
		}
		aldap_freemsg(m);
	}
	goto end;

error:
	ret = -1;
	if (ldapattrsp)
		aldap_free_attr(ldapattrsp);

end:
	if (m)
		aldap_freemsg(m);

	return ret;
}

static int
table_ldap_credentials(struct table_ldap_handle *tlh, const char *key, void **retp)
{
	struct aldap		       *aldap = tlh->aldap;
	struct table		       *cfg = table_get_configuration(tlh->table);
	const char		       *filter = NULL;
	const char		       *basedn = NULL;
	struct credentials     	       *credentials = NULL;
	char			       *expfilter = NULL;
	char     		      **attributes = NULL;
	char     		       *ret_attr[4];
	char			       *attr;
	char				line[1024];
	int				ret = -1;

	basedn = table_get(cfg, "basedn");
	if ((filter = table_get(cfg, "credentials_filter")) == NULL) {
		log_warnx("table_ldap: lookup: no filter configured for credentials");
		goto end;
	}

	if ((attr = table_get(cfg, "credentials_attributes")) == NULL) {
		log_warnx("table_ldap: lookup: no attributes configured for credentials");
		goto end;
	}

	if (! filter_expand(&expfilter, filter, key)) {
		log_warnx("table_ldap: lookup: couldn't expand filter");
		goto end;
	}

	if (! parse_attributes(&attributes, attr, 2)) {
		log_warnx("table_ldap: lookup: failed to parse attributes");
		goto end;
	}

	ret = ldap_query_single_entry(aldap, basedn, expfilter, attributes, &ret_attr);
	if (ret == -1)
		goto end;
	if (ret) {
		if (retp) {
			snprintf(line, sizeof line, "%s:%s", ret_attr[0], ret_attr[1]);
			log_debug("line: %s", line);
			credentials = xcalloc(1, sizeof(struct credentials), "");
			//if (! text_to_userinfo(userinfo, line))
			//	goto end;
			*retp = credentials;
		}
	}

end:
	free(expfilter);
	free(attributes);
	return ret;
}

static int
table_ldap_userinfo(struct table_ldap_handle *tlh, const char *key, void **retp)
{
	struct aldap		       *aldap = tlh->aldap;
	struct table		       *cfg = table_get_configuration(tlh->table);
	const char		       *filter = NULL;
	const char		       *basedn = NULL;
	struct userinfo		       *userinfo = NULL;
	char			       *expfilter = NULL;
	char     		      **attributes = NULL;
	char     		       *ret_attr[4];
	char			       *attr;
	char				line[1024];
	int				ret = -1;

	basedn = table_get(cfg, "basedn");
	if ((filter = table_get(cfg, "userinfo_filter")) == NULL) {
		log_warnx("table_ldap: lookup: no filter configured for userinfo");
		goto end;
	}

	if ((attr = table_get(cfg, "userinfo_attributes")) == NULL) {
		log_warnx("table_ldap: lookup: no attributes configured for userinfo");
		goto end;
	}

	if (! filter_expand(&expfilter, filter, key)) {
		log_warnx("table_ldap: lookup: couldn't expand filter");
		goto end;
	}

	if (! parse_attributes(&attributes, attr, 4)) {
		log_warnx("table_ldap: lookup: failed to parse attributes");
		goto end;
	}

	ret = ldap_query_single_entry(aldap, basedn, expfilter, attributes, &ret_attr);
	if (ret == -1)
		goto end;
	if (ret) {
		if (retp) {
			snprintf(line, sizeof line, "%s:%s:%s:%s",
			    ret_attr[0], ret_attr[1], ret_attr[2], ret_attr[3]);
			log_debug("line: %s", line);
			userinfo = xcalloc(1, sizeof(struct userinfo), "");
			if (! text_to_userinfo(userinfo, line))
				goto end;
			*retp = userinfo;
		}
	}

end:
	free(expfilter);
	free(attributes);
	return ret;
}

static struct aldap *
ldap_client_connect(const char *addr)
{
	struct aldap_url	lu;
	struct addrinfo		 hints, *res0, *res;
	int			 error;

	char *url;
	int fd = -1;

	if ((url = strdup(addr)) == NULL)
		err(1, NULL);

	if (aldap_parse_url(url, &lu) != 1) {
		warnx("aldap_parse_url fail");
		goto err;
	}

	bzero(&hints, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM; /* DUMMY */
	error = getaddrinfo(lu.host, NULL, &hints, &res0);
	if (error == EAI_AGAIN || error == EAI_NODATA || error == EAI_NONAME)
		goto err;
	if (error) {
		log_warnx("ldap_client_connect: could not parse \"%s\": %s", lu.host,
		    gai_strerror(error));
		goto err;
	}

	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family != AF_INET && res->ai_family != AF_INET6)
			continue;

		fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (fd == -1)
			continue;

		if (res->ai_family == AF_INET) {
			struct sockaddr_in sin4 = *(struct sockaddr_in *)res->ai_addr;
			sin4.sin_port = htons(lu.port);
			if (connect(fd, (struct sockaddr *)&sin4, res->ai_addrlen) == 0)
				return aldap_init(fd);
		}
		else if (res->ai_family == AF_INET6) {
			struct sockaddr_in6 sin6 = *(struct sockaddr_in6 *)res->ai_addr;
			sin6.sin6_port = htons(lu.port);
			if (connect(fd, (struct sockaddr *)&sin6, res->ai_addrlen) == 0)
				return aldap_init(fd);
		}

		close(fd);
	}

err:
	if (fd != -1)
		close(fd);
	free(url);
	return NULL;
}

static int
parse_attributes(char ***attributes, const char *line, size_t expect)
{
	char	buffer[1024];
	char   *p;
	int	m, n;
	char   **attr;

	if (strlcpy(buffer, line, sizeof buffer)
	    >= sizeof buffer)
		return 0;

	m = 1;
	for (p = buffer; *p; ++p) {
		if (*p == ',') {
			*p = 0;
			m++;
		}
	}
	if (expect != m)
		return 0;

	attr = xcalloc(m+1, sizeof (char *), "parse_attributes");
	p = buffer;
	for (n = 0; n < m; ++n) {
		attr[n] = xstrdup(p, "parse_attributes");
		p += strlen(p) + 1;
	}
	*attributes = attr;
	return 1;
}
