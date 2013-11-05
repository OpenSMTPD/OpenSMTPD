include $(top_srcdir)/mk/pathnames
include $(top_srcdir)/mk/filter.mk

pkglibexec_PROGRAMS	 = filter-dnsbl

filter_dnsbl_SOURCES	 = $(SRCS)
filter_dnsbl_SOURCES	+= $(filters_srcdir)/filter_dnsbl.c
filter_dnsbl_SOURCES	+= $(filters_srcdir)/asr_event.c

filter_dnsbl_SOURCES	+= $(asr_srcdir)/asr.c
filter_dnsbl_SOURCES	+= $(asr_srcdir)/asr_debug.c
filter_dnsbl_SOURCES	+= $(asr_srcdir)/asr_utils.c
filter_dnsbl_SOURCES	+= $(asr_srcdir)/gethostnamadr_async.c
filter_dnsbl_SOURCES	+= $(asr_srcdir)/res_send_async.c
filter_dnsbl_SOURCES	+= $(asr_srcdir)/getaddrinfo_async.c
filter_dnsbl_SOURCES	+= $(asr_srcdir)/getnameinfo_async.c
filter_dnsbl_SOURCES	+= $(asr_srcdir)/res_search_async.c

filter_dnsbl_CFLAGS	= -DASR_OPT_THREADSAFE=0
