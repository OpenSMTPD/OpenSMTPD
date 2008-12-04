#	$OpenBSD: Makefile,v 1.4 2008/12/03 20:11:35 gilles Exp $

.include <bsd.own.mk>

SUBDIRS = makemap newaliases smtpd

distribution:
	${INSTALL} -C -o root -g wheel -m 0644 ${.CURDIR}/smtpd.conf \
		${DESTDIR}/etc/mail/smtpd.conf

.include <bsd.subdir.mk>
