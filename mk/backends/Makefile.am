SUBDIRS =	queue-stub
SUBDIRS+=	queue-null
SUBDIRS+=	queue-ram

SUBDIRS+=	scheduler-stub
SUBDIRS+=	scheduler-ram

SUBDIRS+=	table-stub
SUBDIRS+=	table-passwd

if HAVE_MYSQL
SUBDIRS+=	table-mysql
endif

if HAVE_POSTGRES
SUBDIRS+=	table-postgres
endif

if HAVE_LDAP
SUBDIRS+=	table-ldap
endif

if HAVE_SQLITE
SUBDIRS+=	table-sqlite
endif

if HAVE_REDIS
SUBDIRS+=	table-redis
endif

if HAVE_SOCKETMAP
SUBDIRS+=	table-socketmap
endif
