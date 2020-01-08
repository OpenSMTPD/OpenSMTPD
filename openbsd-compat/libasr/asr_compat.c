/*	$OpenBSD: asr_debug.c,v 1.25 2018/04/28 15:16:49 schwarze Exp $	*/
/*
 * Copyright (c) 2012 Eric Faurot <eric@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <arpa/nameser.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif

#include "asr_compat.h"

#ifndef HAVE___P_CLASS
const char *
__p_class(int c)
{
	switch(c) {
	case C_IN:	return "IN";
	case C_CHAOS:	return "CHAOS";
	case C_HS:	return "HESIOD";
	case C_ANY:	return "ANY";
	default:	return "?";
	}
};
#endif /* !HAVE___P_CLASS */

#ifndef HAVE___P_TYPE
const char *
__p_type(int t)
{
	switch(t) {
	case T_A:	return "A";
	case T_NS:	return "NS";
	case T_MD:	return "MD";
	case T_MF:	return "MF";
	case T_CNAME:	return "CNAME";
	case T_SOA:	return "SOA";
	case T_MB:	return "MB";
	case T_MG:	return "MG";
	case T_MR:	return "MR";
	case T_NULL:	return "NULL";
	case T_WKS:	return "WKS";
	case T_PTR:	return "PTR";
	case T_HINFO:	return "HINFO";
	case T_MINFO:	return "MINFO";
	case T_MX:	return "MX";
	case T_TXT:	return "TXT";
	case T_RP:	return "RP";
	case T_AFSDB:	return "AFSDB";
	case T_X25:	return "X25";
	case T_ISDN:	return "ISDN";
	case T_RT:	return "RT";
	case T_NSAP:	return "NSAP";
	case T_NSAP_PTR:return"NSAP_PTR";
	case T_SIG:	return "SIG";
	case T_KEY:	return "KEY";
	case T_PX:	return "PX";
	case T_GPOS:	return "GPOS";
	case T_AAAA:	return "AAAA";
	case T_LOC:	return "LOC";
	case T_NXT:	return "NXT";
	case T_EID:	return "EID";
	case T_NIMLOC:	return "NIMLOC";
	case T_SRV:	return "SRV";
	case T_ATMA:	return "ATMA";
	case T_OPT:	return "OPT";
	case T_IXFR:	return "IXFR";
	case T_AXFR:	return "AXFR";
	case T_MAILB:	return "MAILB";
	case T_MAILA:	return "MAILA";
#ifdef T_UINFO
	case T_UINFO:	return "UINFO";
#endif
#ifdef T_UID
	case T_UID:	return "UID";
#endif
#ifdef T_GID
	case T_GID:	return "GID";
#endif
	case T_NAPTR:	return "NAPTR";
#ifdef T_UNSPEC
	case T_UNSPEC:	return "UNSPEC";
#endif
	case T_ANY:	return "ANY";
	default:	return "?";
	}
}
#endif /* !HAVE___P_TYPE */
