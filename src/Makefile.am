bin_PROGRAMS = makemap smtpd smtpctl

makemap_SOURCES = 	parse.y makemap.c aliases.c map.c log.c util.c

smtpd_SOURCES =		parse.y log.c config.c buffer.c imsg.c			\
			smtpd.c lka.c mfa.c queue.c mta.c mda.c control.c	\
			smtp.c  smtp_session.c store.c 				\
			ssl.c ssl_privsep.c dns.c aliases.c forward.c		\
			map.c runner.c util.c queue_shared.c

smtpctl_SOURCES = 	smtpctl.c parser.c buffer.c imsg.c log.c enqueue.c queue_shared.c util.c

YACC = byacc

INCLUDES = -I$(top_srcdir)/openbsd-compat/

LIBCOMPAT=$(top_srcdir)/openbsd-compat/libopenbsd-compat.a

LDADD = $(LIBCOMPAT) -levent -lssl -ldb1 -lcrypt -lkeynote -lutil

#makemap newaliases
install-exec-hook:
	rm -rf	$(DESTDIR)$(bindir)/newaliases$(EXEEXT)

	ln $(DESTDIR)$(bindir)/makemap$(EXEEXT) \
		$(DESTDIR)$(bindir)/newaliases$(EXEEXT)
