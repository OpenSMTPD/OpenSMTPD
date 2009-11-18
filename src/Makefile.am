bin_PROGRAMS = makemap smtpd smtpctl

makemap_SOURCES = 	parse.y makemap.c aliases.c expand.c map.c log.c util.c

smtpd_SOURCES=		aliases.c authenticate.c bounce.c buffer.c client.c	\
			config.c control.c dns.c expand.c forward.c imsg.c	\
			lka.c log.c map.c mda.c mfa.c mta.c parse.y queue.c	\
			queue_shared.c ruleset.c runner.c smtp.c smtp_session.c	\
			smtpd.c ssl.c ssl_privsep.c util.c

smtpctl_SOURCES = 	smtpctl.c parser.c buffer.c imsg.c log.c enqueue.c      \
			queue_shared.c util.c client.c
smtpctl_CFLAGS=		-DCLIENT_NO_SSL

YACC = byacc

INCLUDES = -I$(top_srcdir)/openbsd-compat/

LIBCOMPAT=$(top_srcdir)/openbsd-compat/libopenbsd-compat.a

LDADD = $(LIBCOMPAT) -levent -lssl -ldb1 -lcrypt -lutil

#makemap newaliases
install-exec-hook:
	rm -rf	$(DESTDIR)$(bindir)/newaliases$(EXEEXT)

	ln $(DESTDIR)$(bindir)/makemap$(EXEEXT) \
		$(DESTDIR)$(bindir)/newaliases$(EXEEXT)
