pkglibexec_PROGRAMS=	backend-queue-null backend-queue-ram backend-queue-stub
if HAVE_LDAP
pkglibexec_PROGRAMS+=	backend-table-ldap
endif
if HAVE_SQLITE
pkglibexec_PROGRAMS+=	backend-table-sqlite
endif
pkglibexec_PROGRAMS+=	backend-table-stub

INCLUDES=		-I$(top_srcdir)/smtpd					\
			-I$(top_srcdir)/openbsd-compat

LIBCOMPAT=		$(top_builddir)/openbsd-compat/libopenbsd-compat.a

LDADD=			$(LIBCOMPAT)

SRCS=			../log.c

backend_queue_null_SOURCES=$(SRCS) ../queue_api.c queue_utils.c queue_null.c

backend_queue_ram_SOURCES=$(SRCS) ../queue_api.c queue_utils.c queue_ram.c ../tree.c

backend_queue_stub_SOURCES=$(SRCS) ../queue_api.c queue_stub.c

if HAVE_LDAP
backend_table_ldap_SOURCES=$(SRCS) table_ldap.c ../table_api.c ../aldap.c ../ber.c
endif

if HAVE_SQLITE
backend_table_sqlite_SOURCES=$(SRCS) table_sqlite.c ../table_api.c
endif

backend_table_stub_SOURCES=$(SRCS) table_stub.c ../table_api.c