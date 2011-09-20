if !HAVE_MAIL_LOCAL
SUBDIRS=libexec
endif

bin_PROGRAMS = makemap smtpd smtpctl

makemap_SOURCES = 	parse.y makemap.c aliases.c expand.c map.c map_backend.c\
			map_backend_db.c map_backend_stdio.c log.c util.c

smtpd_SOURCES=		aliases.c auth_backend.c bounce.c client.c		\
			config.c control.c dns.c expand.c forward.c		\
			lka.c lka_session.c log.c map.c map_backend.c		\
			map_backend_db.c map_backend_stdio.c			\
			mda.c mfa.c mfa_session.c mta.c parse.y 		\
			queue.c queue_shared.c ruleset.c runner.c smtp.c 	\
			smtp_session.c smtpd.c ssl.c ssl_privsep.c util.c asr.c \
			print.c pack.c dname.c res_random.c sockaddr.c 		\
			ramqueue.c queue_backend.c queue_fsqueue.c		\
			user_backend.c stats.c

smtpctl_SOURCES = 	smtpctl.c parser.c log.c enqueue.c queue_shared.c util.c\
		       	client.c queue_backend.c queue_fsqueue.c stats.c
smtpctl_CFLAGS=		-DCLIENT_NO_SSL

INCLUDES = -I$(top_srcdir)/openbsd-compat/

LIBCOMPAT=$(top_srcdir)/openbsd-compat/libopenbsd-compat.a

LDADD = $(LIBCOMPAT) -levent -lssl -lcrypt -lutil

# need to define _GNU_SOURCE to get:
# EAI_NODATA defined
# {v,}asprintf
# setres{g,u}id
CFLAGS=-D_GNU_SOURCE

# makemap newaliases
install-exec-hook:
	rm -rf	$(DESTDIR)$(bindir)/newaliases$(EXEEXT)

	ln $(DESTDIR)$(bindir)/makemap$(EXEEXT) \
		$(DESTDIR)$(bindir)/newaliases$(EXEEXT)
