/*
 * Copyright (c) 1987, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* OPENBSD ORIGINAL: lib/libc/stdlib/getopt.c */

#include "includes.h"
#if !defined(HAVE_GETOPT) || !defined(HAVE_GETOPT_OPTRESET)

#if defined(LIBC_SCCS) && !defined(lint)
static char *rcsid = "$OpenBSD: getopt.c,v 1.5 2003/06/02 20:18:37 millert Exp $";
#endif /* LIBC_SCCS and not lint */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int	BSDopterr = 1,		/* if error message should be printed */
	BSDoptind = 1,		/* index into parent argv vector */
	BSDoptopt,		/* character checked for validity */
	BSDoptreset;		/* reset getopt */
char	*BSDoptarg;		/* argument associated with option */

#define	BADCH	(int)'?'
#define	BADARG	(int)':'
#define	EMSG	""

/*
 * getopt --
 *	Parse argc/argv argument vector.
 */
int
BSDgetopt(nargc, nargv, ostr)
	int nargc;
	char * const *nargv;
	const char *ostr;
{
	extern char *__progname;
	static char *place = EMSG;		/* option letter processing */
	char *oli;				/* option letter list index */

	if (ostr == NULL)
		return (-1);

	if (BSDoptreset || !*place) {		/* update scanning pointer */
		BSDoptreset = 0;
		if (BSDoptind >= nargc || *(place = nargv[BSDoptind]) != '-') {
			place = EMSG;
			return (-1);
		}
		if (place[1] && *++place == '-') {	/* found "--" */
			++BSDoptind;
			place = EMSG;
			return (-1);
		}
	}					/* option letter okay? */
	if ((BSDoptopt = (int)*place++) == (int)':' ||
	    !(oli = strchr(ostr, BSDoptopt))) {
		/*
		 * if the user didn't specify '-' as an option,
		 * assume it means -1.
		 */
		if (BSDoptopt == (int)'-')
			return (-1);
		if (!*place)
			++BSDoptind;
		if (BSDopterr && *ostr != ':')
			(void)fprintf(stderr,
			    "%s: illegal option -- %c\n", __progname, BSDoptopt);
		return (BADCH);
	}
	if (*++oli != ':') {			/* don't need argument */
		BSDoptarg = NULL;
		if (!*place)
			++BSDoptind;
	}
	else {					/* need an argument */
		if (*place)			/* no white space */
			BSDoptarg = place;
		else if (nargc <= ++BSDoptind) {	/* no arg */
			place = EMSG;
			if (*ostr == ':')
				return (BADARG);
			if (BSDopterr)
				(void)fprintf(stderr,
				    "%s: option requires an argument -- %c\n",
				    __progname, BSDoptopt);
			return (BADCH);
		}
	 	else				/* white space */
			BSDoptarg = nargv[BSDoptind];
		place = EMSG;
		++BSDoptind;
	}
	return (BSDoptopt);			/* dump back option letter */
}

#endif /* !defined(HAVE_GETOPT) || !defined(HAVE_OPTRESET) */
