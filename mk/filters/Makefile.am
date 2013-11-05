include $(top_srcdir)/mk/pathnames

SRCS=			$(smtpd_srcdir)/filter_api.c
SRCS+=			$(smtpd_srcdir)/mproc.c
SRCS+=			$(smtpd_srcdir)/log.c
SRCS+=			$(smtpd_srcdir)/tree.c
SRCS+=			$(smtpd_srcdir)/util.c
SRCS+=			$(smtpd_srcdir)/csprng.c
SRCS+=			$(smtpd_srcdir)/iobuf.c
SRCS+=			$(smtpd_srcdir)/ioev.c

AM_CPPFLAGS=		-I$(smtpd_srcdir)	\
			-I$(compat_srcdir)	\
			-I$(asr_srcdir)

LIBCOMPAT=		$(top_builddir)/openbsd-compat/libopenbsd-compat.a

LDADD=			$(LIBCOMPAT)

CFLAGS=			-DNO_IO -DBUILD_FILTER

pkglibexec_PROGRAMS=filter-dnsbl filter-monkey filter-stub filter-trace

filter_dnsbl_SOURCES = $(SRCS)
filter_dnsbl_SOURCES+= $(filters_srcdir)/filter_dnsbl.c
filter_dnsbl_SOURCES+= $(filters_srcdir)/asr_event.c

# resolver
filter_dnsbl_SOURCES+=	$(asr_srcdir)/asr.c					\
			$(asr_srcdir)/asr_debug.c				\
			$(asr_srcdir)/asr_utils.c				\
			$(asr_srcdir)/gethostnamadr_async.c			\
			$(asr_srcdir)/res_send_async.c				\
			$(asr_srcdir)/getaddrinfo_async.c			\
			$(asr_srcdir)/getnameinfo_async.c			\
			$(asr_srcdir)/res_search_async.c

filter_dnsbl_CFLAGS=	-DASR_OPT_THREADSAFE=0

filter_monkey_SOURCES=	$(SRCS)
filter_monkey_SOURCES+=	$(filters_srcdir)/filter_monkey.c

filter_stub_SOURCES=	$(SRCS)
filter_stub_SOURCES+=	$(filters_srcdir)/filter_stub.c

filter_trace_SOURCES=	$(SRCS)
filter_trace_SOURCES+=	$(filters_srcdir)/filter_trace.c

#EXTRA_DIST=		$(filters_srcdir)/asr_event.h				\
			$(asr_srcdir)/asr.h					\
			$(asr_srcdir)/asr_private.h
