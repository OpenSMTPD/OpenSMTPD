SRCS    = ../filter_api.c ../mproc.c ../log.c ../tree.c ../util.c

INCLUDES=		-I$(top_srcdir)/smtpd					\
			-I$(top_srcdir)/openbsd-compat				\
			-I$(top_srcdir)/contrib/lib/libc/asr

LIBCOMPAT=		$(top_builddir)/openbsd-compat/libopenbsd-compat.a

LDADD=			$(LIBCOMPAT)

CFLAGS=			-DNO_IO -DBUILD_FILTER

pkglibexec_PROGRAMS=filter-dnsbl filter-monkey filter-stub filter-trace

filter_dnsbl_SOURCES = $(SRCS)
filter_dnsbl_SOURCES+= filter_dnsbl.c asr_event.c

# resolver
asr_srcdir=		$(top_srcdir)/contrib/lib/libc/asr

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
filter_monkey_SOURCES+=	filter_monkey.c

filter_stub_SOURCES=	$(SRCS)
filter_stub_SOURCES+=	filter_stub.c

filter_trace_SOURCES=	$(SRCS)
filter_trace_SOURCES+=	filter_trace.c

EXTRA_DIST=		asr_event.h						\
			$(asr_srcdir)/asr.h					\
			$(asr_srcdir)/asr_private.h
