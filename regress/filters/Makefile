CFLAGS	=	-I../../smtpd/
LDFLAGS	=	-L../../smtpd/libsmtpdfilter -lsmtpdfilter -levent -lutil

FILTERS	=	helo_accept
FILTERS+=	helo_reject_temp
FILTERS+=	helo_reject_perm

INSTALLPATH=	/usr/libexec/smtpd/

all:
.for FILTER in $(FILTERS)
	$(CC) -o $(INSTALLPATH)/$(FILTER) $(CFLAGS) $(FILTER).c $(LDFLAGS)
.endfor
