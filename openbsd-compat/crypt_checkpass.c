/* OPENBSD ORIGINAL: lib/libc/crypt/cryptutil.c */

#include <errno.h>
#include <string.h>
#include <unistd.h>

int
crypt_checkpass(const char *pass, const char *goodhash)
{
	if (goodhash == NULL)
		goto fail;

	/* empty password */
	if (strlen(goodhash) == 0 && strlen(pass) == 0)
		return 0;

	if (strcmp(crypt(pass, goodhash), goodhash) == 0)
		return 0;

fail:
	errno = EACCES;
	return -1;
}
