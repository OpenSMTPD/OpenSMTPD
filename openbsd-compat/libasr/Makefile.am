noinst_LIBRARIES = libasr.a

libasr_a_SOURCES  =	asr.c
libasr_a_SOURCES +=	asr_debug.c
libasr_a_SOURCES +=	asr_compat.c
libasr_a_SOURCES +=	asr_utils.c
libasr_a_SOURCES +=    event_asr_run.c
libasr_a_SOURCES +=	getaddrinfo_async.c
libasr_a_SOURCES +=	gethostnamadr_async.c
libasr_a_SOURCES +=	getnameinfo_async.c
libasr_a_SOURCES +=	getnetnamadr_async.c
libasr_a_SOURCES +=	res_search_async.c
libasr_a_SOURCES +=	res_send_async.c

include_HEADERS =	asr.h

libasr_a_CPPFLAGS =	-I$(builddir)/..
libasr_a_LIBADD =	$(builddir)/../libopenbsd.a

EXTRA_DIST =		asr_compat.h
EXTRA_DIST +=		asr_private.h
