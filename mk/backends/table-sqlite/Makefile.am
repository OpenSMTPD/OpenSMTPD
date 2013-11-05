include	$(top_srcdir)/mk/pathnames
include	$(top_srcdir)/mk/table.mk

pkglibexec_PROGRAMS	 = table-sqlite

table_sqlite_SOURCES	 = $(SRCS)
table_sqlite_SOURCES	+= $(smtpd_srcdir)/table_sqlite.c

LDADD	+= -lsqlite3
