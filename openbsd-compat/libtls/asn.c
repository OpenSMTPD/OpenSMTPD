/* $OpenBSD: a_time_tm.c,v 1.16 2020/12/16 18:35:59 tb Exp $ */
/*
 * Copyright (c) 2015 Bob Beck <beck@openbsd.org>
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

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define GENTIME_LENGTH 15
#define UTCTIME_LENGTH 13

#define V_ASN1_UTCTIME		23
#define V_ASN1_GENERALIZEDTIME	24

int
ASN1_time_tm_cmp(struct tm *tm1, struct tm *tm2)
{
	if (tm1->tm_year < tm2->tm_year)
		return (-1);
	if (tm1->tm_year > tm2->tm_year)
		return (1);
	if (tm1->tm_mon < tm2->tm_mon)
		return (-1);
	if (tm1->tm_mon > tm2->tm_mon)
		return (1);
	if (tm1->tm_mday < tm2->tm_mday)
		return (-1);
	if (tm1->tm_mday > tm2->tm_mday)
		return (1);
	if (tm1->tm_hour < tm2->tm_hour)
		return (-1);
	if (tm1->tm_hour > tm2->tm_hour)
		return (1);
	if (tm1->tm_min < tm2->tm_min)
		return (-1);
	if (tm1->tm_min > tm2->tm_min)
		return (1);
	if (tm1->tm_sec < tm2->tm_sec)
		return (-1);
	if (tm1->tm_sec > tm2->tm_sec)
		return (1);
	return 0;
}

int
ASN1_time_tm_clamp_notafter(struct tm *tm)
{
#ifdef SMALL_TIME_T
	struct tm broken_os_epoch_tm;
	time_t broken_os_epoch_time = INT_MAX;

	if (gmtime_r(&broken_os_epoch_time, &broken_os_epoch_tm) == NULL)
		return 0;

	if (ASN1_time_tm_cmp(tm, &broken_os_epoch_tm) == 1)
		memcpy(tm, &broken_os_epoch_tm, sizeof(*tm));
#endif
	return 1;
}
