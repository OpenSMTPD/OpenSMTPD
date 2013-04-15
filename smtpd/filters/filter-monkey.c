#include <stdio.h>
#include <inttypes.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"


static void
monkey(uint64_t qid)
{
	uint32_t r;

	r = arc4random_uniform(100);
	if (r < 70)
		filter_api_accept(qid);
	else if (r < 90)
		filter_api_reject_code(qid, FILTER_FAIL, 666,
		    "I am a monkey!");
	else
		filter_api_reject_code(qid, FILTER_CLOSE, 666,
		    "I am a funny monkey!");
}

static void
on_connect(uint64_t id, uint64_t qid, struct filter_connect *conn)
{
	monkey(qid);
}

static void
on_helo(uint64_t id, uint64_t qid, const char *helo)
{
	monkey(qid);
}

static void
on_mail(uint64_t id, uint64_t qid, struct mailaddr *mail)
{
	monkey(qid);
}

static void
on_rcpt(uint64_t id, uint64_t qid, struct mailaddr *rcpt)
{
	monkey(qid);
}

static void
on_data(uint64_t id, uint64_t qid)
{
	monkey(qid);
}

static void
on_eom(uint64_t id, uint64_t qid)
{
	monkey(qid);
}

int
main(int argc, char **argv)
{
	filter_api_on_connect(on_connect);
	filter_api_on_helo(on_helo);
	filter_api_on_mail(on_mail);
	filter_api_on_rcpt(on_rcpt);
	filter_api_on_data(on_data);
	filter_api_on_eom(on_eom);
	filter_api_loop();
	return (1);
}
