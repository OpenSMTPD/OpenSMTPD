/*
 * Public domain
 * err.h compatibility shim
 */

#ifndef HAVE_ERR_H

#ifndef LIBCRYPTOCOMPAT_ERR_H
#define LIBCRYPTOCOMPAT_ERR_H

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define err(exitcode, format, args...) \
  errx(exitcode, format ": %s", ## args, strerror(errno))

#define errx(exitcode, format, args...) \
  do { warnx(format, ## args); exit(exitcode); } while (0)

#define warn(format, args...) \
  warnx(format ": %s", ## args, strerror(errno))

#define warnx(format, args...) \
  fprintf(stderr, format "\n", ## args)

#endif

#endif
