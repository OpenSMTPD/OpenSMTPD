#	$OpenBSD$

.PATH:		${.CURDIR}/..

PROG=	smtpctl
BINOWN=	root

BINMODE?=555

BINDIR=	/usr/bin
MAN=	smtpctl.8

SRCS=	smtpctl.c parser.c buffer.c imsg.c log.c
LDFLAGS=	-lutil
.include <bsd.prog.mk>
