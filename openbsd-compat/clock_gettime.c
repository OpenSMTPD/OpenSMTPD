/*
 * Copyright (c) 2012 Charles Longeau <chl@openbsd.org>
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

#ifdef HAVE_MACH_MACH_TIME_H
#include <mach/mach_time.h>
#endif
#include <sys/time.h>
#include <time.h>

#if !defined(HAVE_CLOCK_GETTIME)
int
clock_gettime(int clock_id, struct timespec *tp)
{
	int				ret = 0;
	uint64_t			time;
	mach_timebase_info_data_t	info;
	static double			scaling_factor = 0;

#if 0
	struct timeval			tv;

	ret = gettimeofday(&tv, NULL);
	TIMEVAL_TO_TIMESPEC(&tv, tp);
#endif

/* based on http://code-factor.blogspot.fr/2009/11/monotonic-timers.html */

	time = mach_absolute_time();

	if (scaling_factor == 0) {
		ret = (int) mach_timebase_info(&info);
		if (ret != 0)
			fatal("mach_timebase_info failed");
		scaling_factor = info.numer/info.denom;
	}

	time *= scaling_factor;

	tp->tv_sec = time / 1000000000;
	tp->tv_nsec = time % 1000000000;

	return (ret);
}
#endif
