.PATH: ${.CURDIR}/.. ${.CURDIR}/../..

PROG=   filter-perl
SRCS=   filter_perl.c

CFLAGS+= `perl -MExtUtils::Embed -e ccopts`
LDADD+= `perl -MExtUtils::Embed -e ldopts`

NOMAN=  noman

.include <bsd.prog.mk>
