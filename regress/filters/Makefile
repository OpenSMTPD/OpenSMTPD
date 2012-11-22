CFLAGS	=	-I../../smtpd/
LDFLAGS	=	-L../../smtpd/libsmtpdfilter -lsmtpdfilter -levent -lutil

SRCS	=	filter.c

INSTALLPATH=	/usr/libexec/smtpd

all:
	$(CC) -o $(INSTALLPATH)/filter $(CFLAGS) $(SRCS) $(LDFLAGS)
