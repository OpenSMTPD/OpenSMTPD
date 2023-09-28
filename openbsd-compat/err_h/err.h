#ifndef ERR_H
#define ERR_H

# include <stdarg.h>
__dead void	 err(int, const char *, ...);
__dead void	 errc(int, int, const char *, ...);
__dead void	 errx(int, const char *, ...);
void		 warn(const char *, ...);
void		 warnc(int, const char *, ...);
void		 warnx(const char *, ...);
__dead void	 verr(int, const char *, va_list);
__dead void	 verrc(int, int, const char *, va_list);
__dead void	 verrx(int, const char *, va_list);
void		 vwarn(const char *, va_list);
void		 vwarnc(int, const char *, va_list);
void		 vwarnx(const char *, va_list);

#endif
