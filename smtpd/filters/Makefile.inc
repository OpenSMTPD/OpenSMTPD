#	$OpenBSD$

CFLAGS	+= -DNO_IO -DBUILD_FILTER
CPPFLAGS+= -I../../

SRCS	+= filter_api.c mproc.c log.c tree.c util.c

#SRCS	+= filter_api.c dict.c tree.c util.c iobuf.c

LDADD	+= -levent -lutil

BINDIR	= /usr/libexec/smtpd
