#	$OpenBSD$

CFLAGS	+= -DNO_IO
CPPFLAGS+= -I${.CURDIR}/../../

SRCS	+= log.c

LDADD	+= -lutil

CFLAGS+=	-g3 -ggdb -I${.CURDIR}/.. -I/usr/src/lib/libc/asr
CFLAGS+=	-Wall -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=	-Wsign-compare -Wbounded
#CFLAGS+=	-Werror # during development phase (breaks some archs) 

BINDIR	= /usr/libexec/smtpd
