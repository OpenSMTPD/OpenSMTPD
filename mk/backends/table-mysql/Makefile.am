include	$(top_srcdir)/mk/pathnames
include	$(top_srcdir)/mk/table.mk

pkglibexec_PROGRAMS	 = table-mysql

table_mysql_SOURCES	 = $(SRCS)
table_mysql_SOURCES	+= $(smtpd_srcdir)/table_mysql.c

LDADD	+= -lmysqlclient
