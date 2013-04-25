#	$OpenBSD: Makefile,v 1.3 2012/08/02 13:38:39 okan Exp $

CFLAGS	+= -DNO_IO
CPPFLAGS+= -I../../

QUEUE_SRCS=

LDADD	+= -lutil

CFLAGS+=	-g3 -ggdb -I${.CURDIR}/.. -I/usr/src/lib/libc/asr
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare -Wbounded
#CFLAGS+=	-Werror # during development phase (breaks some archs) 

BINDIR	= /usr/libexec/smtpd
