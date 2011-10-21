# In OpenBSD, smptd's files are installed this way:
#
# /usr/bin/newaliases --> /usr/sbin/mailwrapper --> /usr/libexec/smtpd/makemap
# /usr/libexec/mail.local
# /usr/sbin/makemap   --> /usr/sbin/mailwrapper --> /usr/libexec/smtpd/makemap
# /usr/sbin/smtpctl
# /usr/sbin/smtpd
#
#
# For OpenSMTPD portable, here's where files are installed:
# (assuming PREFIX=/usr/local)
#
# /usr/local/bin/newaliases --> /usr/local/libexec/opensmtpd-portable/makemap
# /usr/local/libexec/mail.local
# /usr/local/libexec/opensmtpd-portable/makemap
# /usr/local/sbin/smtpctl
# /usr/local/sbin/smtpd


if !HAVE_MAIL_LOCAL
SUBDIRS =		libexec
endif

sbin_PROGRAMS =		smtpd smtpctl
pkglibexec_PROGRAMS =	makemap

makemap_SOURCES =	parse.y makemap.c aliases.c expand.c map.c map_backend.c\
			map_backend_db.c map_backend_stdio.c log.c util.c

smtpd_SOURCES =		aliases.c auth_backend.c bounce.c client.c		\
			config.c control.c dns.c expand.c forward.c		\
			lka.c lka_session.c log.c map.c map_backend.c		\
			map_backend_db.c map_backend_stdio.c			\
			mda.c mfa.c mfa_session.c mta.c parse.y 		\
			queue.c queue_shared.c ruleset.c runner.c smtp.c 	\
			smtp_session.c smtpd.c ssl.c ssl_privsep.c util.c asr.c \
			print.c pack.c dname.c res_random.c sockaddr.c 		\
			ramqueue.c queue_backend.c queue_fsqueue.c		\
			user_backend.c stats.c

smtpctl_SOURCES =	smtpctl.c parser.c log.c enqueue.c queue_shared.c util.c\
		       	client.c queue_backend.c queue_fsqueue.c stats.c
smtpctl_CFLAGS =	-DCLIENT_NO_SSL

EXTRA_DIST = 		asr.h client.h dnsdefs.h dnsutil.h filter.h log.h	\
			parser.h smtpd.h

INCLUDES = 		-I$(top_srcdir)/openbsd-compat

LIBCOMPAT =		$(top_builddir)/openbsd-compat/libopenbsd-compat.a

LDADD = 		$(LIBCOMPAT)

dist_man_MANS =		makemap.8 newaliases.8 smtpctl.8 smtpd.8 smtpd.conf.5

# need to define _GNU_SOURCE to get:
# EAI_NODATA defined
# {v,}asprintf
# setres{g,u}id
CFLAGS =		-D_GNU_SOURCE


# newaliases makemap
install-exec-hook:
	$(MKDIR_P) $(DESTDIR)$(bindir)

	ln -f $(DESTDIR)$(pkglibexecdir)/makemap$(EXEEXT) \
		$(DESTDIR)$(bindir)/newaliases$(EXEEXT)

	ln -f $(DESTDIR)$(pkglibexecdir)/makemap$(EXEEXT) \
		$(DESTDIR)$(sbindir)/makemap$(EXEEXT)

uninstall-hook:
	rm 	$(DESTDIR)$(bindir)/newaliases$(EXEEXT) \
		$(DESTDIR)$(sbindir)/makemap$(EXEEXT)
