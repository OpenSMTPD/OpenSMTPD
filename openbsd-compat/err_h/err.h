#ifndef ERR_H
#define ERR_H

#ifndef LIBCRYPTOCOMPAT_ERR_H
#define LIBCRYPTOCOMPAT_ERR_H

__attribute__ ((noreturn))
void err(int, const char *, ...);

__attribute__ ((noreturn))
void errx(int, const char *, ...);

void warn(const char *, ...);
void warnx(const char *, ...);

#endif

#endif
