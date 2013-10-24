pkglibexec_PROGRAMS =	encrypt	

encrypt_SOURCES =	encrypt.c

CFLAGS +=		-D_XOPEN_SOURCE -D_XOPEN_SOURCE_EXTENDED
uninstall-hook:
	rmdir	$(DESTDIR)$(pkglibexecdir) 2> /dev/null || /bin/true
