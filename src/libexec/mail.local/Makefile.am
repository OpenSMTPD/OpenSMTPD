bin_PROGRAMS = mail.local

mail_local_SOURCES = 	mail.local.c locking.c ../../log.c

INCLUDES = -I$(top_srcdir)/openbsd-compat/

LIBCOMPAT=$(top_srcdir)/openbsd-compat/libopenbsd-compat.a

LDADD = $(LIBCOMPAT) -levent -lssl -lcrypt -lutil
