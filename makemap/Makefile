#	$OpenBSD$

.PATH:		${.CURDIR}/..

PROG=	makemap
BINOWN=	root

BINMODE?=555

BINDIR=	/usr/bin
MAN=	makemap.8

SRCS=	makemap.c aliases.c map.c log.c
LDFLAGS=	-lutil
.include <bsd.prog.mk>
