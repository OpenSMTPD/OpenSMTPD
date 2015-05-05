#	$OpenBSD$

.include <bsd.own.mk>

SUBDIR =	smtpd
SUBDIR+=	smtpctl
SUBDIR+=	makemap

uninstall:
	cd smtpd && make uninstall
	cd smtpctl && make uninstall
	cd makemap && make uninstall

.include <bsd.subdir.mk>
