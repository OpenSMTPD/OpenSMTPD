include	$(top_srcdir)/mk/pathnames

pkglibexec_PROGRAMS=	backend-queue-null
pkglibexec_PROGRAMS+=	backend-queue-ram
pkglibexec_PROGRAMS+=	backend-queue-stub

pkglibexec_PROGRAMS+=	backend-scheduler-ram
pkglibexec_PROGRAMS+=	backend-scheduler-stub

if HAVE_LDAP
pkglibexec_PROGRAMS+=	table-ldap
endif
if HAVE_MYSQL
pkglibexec_PROGRAMS+=	table-mysql
endif
if HAVE_POSTGRES
pkglibexec_PROGRAMS+=	table-postgres
endif
if HAVE_SQLITE
pkglibexec_PROGRAMS+=	table-sqlite
endif
pkglibexec_PROGRAMS+=	table-stub


INCLUDES=		-I$(smtpd_srcdir)	\
			-I$(compat_srcdir)

LIBCOMPAT=		$(top_builddir)/openbsd-compat/libopenbsd-compat.a

LDADD=			$(LIBCOMPAT)

QUEUE_SRCS=		$(smtpd_srcdir)/log.c
QUEUE_SRCS+=		$(backends_srcdir)/queue_utils.c
QUEUE_SRCS+=		$(smtpd_srcdir)/queue_api.c

SCHEDULER_SRCS=		$(smtpd_srcdir)/log.c
SCHEDULER_SRCS+=	$(smtpd_srcdir)/scheduler_api.c

TABLE_SRCS=		$(smtpd_srcdir)/log.c
TABLE_SRCS+=		$(smtpd_srcdir)/table_api.c

# queue backends
#

backend_queue_null_SOURCES=	$(QUEUE_SRCS)
backend_queue_null_SOURCES+=	$(backends_srcdir)/queue_null.c

backend_queue_ram_SOURCES=	$(QUEUE_SRCS)
backend_queue_ram_SOURCES+=	$(backends_srcdir)/queue_ram.c
backend_queue_ram_SOURCES+=	$(smtpd_srcdir)/tree.c

backend_queue_stub_SOURCES=	$(QUEUE_SRCS)
backend_queue_stub_SOURCES+=	$(backends_srcdir)/queue_stub.c

# scheduler backends
#

backend_scheduler_ram_SOURCES=	$(SCHEDULER_SRCS)
backend_scheduler_ram_SOURCES+=	$(backends_srcdir)/scheduler_ram.c
backend_scheduler_ram_SOURCES+=	$(smtpd_srcdir)/tree.c

backend_scheduler_stub_SOURCES=	$(SCHEDULER_SRCS)
backend_scheduler_stub_SOURCES+=$(backends_srcdir)/scheduler_stub.c

# table backends
#

if HAVE_LDAP
table_ldap_SOURCES=	$(TABLE_SRCS)
table_ldap_SOURCES+=	$(backends_srcdir)/table_ldap.c
table_ldap_SOURCES+=	$(smtpd_srcdir)/aldap.c
table_ldap_SOURCES+=	$(smtpd_srcdir)/ber.c
endif

if HAVE_MYSQL
table_mysql_SOURCES=	$(TABLE_SRCS)
table_mysql_SOURCES+=	$(backends_srcdir)/table_mysql.c
table_mysql_SOURCES+=	$(smtpd_srcdir)/dict.c
LDADD+=-lmysqlclient
endif

if HAVE_POSTGRES
table_postgres_SOURCES=		$(TABLE_SRCS)
table_postgres_SOURCES+=	$(backends_srcdir)/table_postgres.c
table_postgres_SOURCES+=	$(smtpd_srcdir)/dict.c
LDADD+=-lpq
endif

if HAVE_SQLITE
table_sqlite_SOURCES=	$(TABLE_SRCS)
table_sqlite_SOURCES+=	$(backends_srcdir)/table_sqlite.c
table_sqlite_SOURCES+=	$(smtpd_srcdir)/dict.c
LDADD+=-lsqlite3
endif

table_stub_SOURCES=	$(TABLE_SRCS)
table_stub_SOURCES+=	$(backends_srcdir)/table_stub.c

EXTRA_DIST=		$(backends_srcdir)/queue_utils.h
