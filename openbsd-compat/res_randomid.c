#include "includes.h"

#include <time.h>

unsigned int
res_randomid(void)
{
	struct timespec ts;

	/* This is from musl C library */
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_nsec + ts.tv_nsec / 65536UL & 0xffff;
}
