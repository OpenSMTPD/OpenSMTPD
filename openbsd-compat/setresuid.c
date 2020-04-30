/* Subset of uidswap.c from portable OpenSSH */

/* $OpenBSD: uidswap.c,v 1.35 2006/08/03 03:34:42 deraadt Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Code for uid-swapping.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#include "includes.h"

#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

int setresuid(uid_t ruid, uid_t euid, uid_t suid)
{

#if defined(HAVE_SETRESUID) && !defined(BROKEN_SETRESUID)
	if (setresuid(ruid, euid, suid) < 0)
		fatal("setresuid %u: %.100s", (u_int)ruid, strerror(errno));
#elif defined(HAVE_SETREUID) && !defined(BROKEN_SETREUID)
	if (setreuid(ruid, euid) < 0)
		fatal("setreuid %u: %.100s", (u_int)ruid, strerror(errno));
#else
# ifndef SETEUID_BREAKS_SETUID
	if (seteuid(euid) < 0)
		fatal("seteuid %u: %.100s", (u_int)euid, strerror(errno));
# endif
	if (setuid(ruid) < 0)
		fatal("setuid %u: %.100s", (u_int)ruid, strerror(errno));
#endif
	return (0);
}
