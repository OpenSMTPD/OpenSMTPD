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
filter_dnsbl_SOURCES+=	$(top_srcdir)/contrib/lib/libc/asr/asr.c			\
			$(top_srcdir)/contrib/lib/libc/asr/asr_debug.c			\
			$(top_srcdir)/contrib/lib/libc/asr/asr_utils.c			\
			$(top_srcdir)/contrib/lib/libc/asr/gethostnamadr_async.c	\
			$(top_srcdir)/contrib/lib/libc/asr/res_send_async.c		\
			$(top_srcdir)/contrib/lib/libc/asr/getaddrinfo_async.c		\
			$(top_srcdir)/contrib/lib/libc/asr/getnameinfo_async.c		\
			$(top_srcdir)/contrib/lib/libc/asr/res_search_async.c

filter_dnsbl_CFLAGS=	-DASR_OPT_THREADSAFE=0

filter_monkey_SOURCES=	$(SRCS)
filter_monkey_SOURCES+=	filter_monkey.c

filter_stub_SOURCES=	$(SRCS)
filter_stub_SOURCES+=	filter_stub.c

filter_trace_SOURCES=	$(SRCS)
filter_trace_SOURCES+=	filter_trace.c

