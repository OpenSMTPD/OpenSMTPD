include	$(top_srcdir)/mk/pathnames
include	$(top_srcdir)/mk/table.mk

pkglibexec_PROGRAMS	 = table-redis

table_redis_SOURCES	 = $(SRCS)
table_redis_SOURCES	+= $(smtpd_srcdir)/table_redis.c

CFLAGS	+= -I/usr/local/include/hiredis
LDADD	+= -lhiredis
