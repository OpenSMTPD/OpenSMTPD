
MANPAGES=		makemap.8.out newaliases.8.out
MANPAGES_IN=		$(smtpd_srcdir)/makemap.8
MANPAGES_IN+=		$(smtpd_srcdir)/newaliases.8

EXTRA_DIST=		$(MANPAGES_IN)

PATHSUBS=		-e 's|/usr/libexec|$(libexecdir)|g'			\
			-e 's|/etc/mail/|$(sysconfdir)/|g'

FIXPATHSCMD=		$(SED) $(PATHSUBS)

$(MANPAGES): $(MANPAGES_IN)
	manpage=$(smtpd_srcdir)/`echo $@ | sed 's/\.out$$//'`; \
	if test "$(MANTYPE)" = "man"; then \
		$(FIXPATHSCMD) $${manpage} | $(AWK) -f $(srcdir)/../mdoc2man.awk > $@; \
	else \
		$(FIXPATHSCMD) $${manpage} > $@; \
	fi

# newaliases makemap
install-exec-hook: $(MANPAGES)
	$(MKDIR_P) $(DESTDIR)$(mandir)/$(mansubdir)8
	ln -s $(sbindir)/makemap $(DESTDIR)$(sbindir)/newaliases;

	$(INSTALL) -m 644 makemap.8.out		$(DESTDIR)$(mandir)/$(mansubdir)8/makemap.8
	$(INSTALL) -m 644 newaliases.8.out	$(DESTDIR)$(mandir)/$(mansubdir)8/newaliases.8
	rm makemap.8.out newaliases.8.out

uninstall-hook:
	rm -f	$(DESTDIR)$(sbindir)/newaliases$(EXEEXT) \
		$(DESTDIR)$(sbindir)/makemap$(EXEEXT)
	rm -f	$(DESTDIR)$(mandir)/$(mansubdir)8/makemap.8			\
		$(DESTDIR)$(mandir)/$(mansubdir)8/newaliases.8
	rmdir	$(DESTDIR)$(pkglibexecdir) \
		$(DESTDIR)$(mandir)/$(mansubdir)8 2> /dev/null || /bin/true
