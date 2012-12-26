#include <stdio.h>
#include <inttypes.h>

#include "smtpd-api.h"

static const char *
event_to_str(int hook)
{
	switch (hook) {
	case HOOK_RESET:
		return "RESET";
	case HOOK_DISCONNECT:
		return "DISCONNECT";
	case HOOK_COMMIT:
		return "COMMIT";
	case HOOK_ROLLBACK:
		return "ROLLBACK";
	default:
		return "???";
	}
}

static const char *
status_to_str(int status)
{
	switch (status) {
	case FILTER_OK:
		return "OK";
	case FILTER_FAIL:
		return "FAIL";
	case FILTER_CLOSE:
		return "CLOSE";
	default:
		return "???";
	}
}

static void
on_event(uint64_t id,  enum filter_hook event)
{
	printf("filter-event: id=%016"PRIx64", event=%s\n",
	    id, event_to_str(event));
}

static void
on_notify(uint64_t qid, enum filter_status status)
{
	printf("filter-notify: qid=%016"PRIx64", status=%s\n",
	    qid, status_to_str(status));
}

static void
on_connect(uint64_t id, uint64_t qid, struct filter_connect *conn)
{
	printf("filter-connect: id=%016"PRIx64", qid=%016"PRIx64" hostname=%s\n",
	    id, qid, conn->hostname);
	filter_api_accept_notify(qid);
}

static void
on_helo(uint64_t id, uint64_t qid, const char *helo)
{
	printf("filter: HELO id=%016"PRIx64", qid=%016"PRIx64" %s\n",
	    id, qid, helo);
	filter_api_accept_notify(qid);
}

static void
on_mail(uint64_t id, uint64_t qid, struct filter_mailaddr *mail)
{
	printf("filter: MAIL id=%016"PRIx64", qid=%016"PRIx64" %s@%s\n",
	    id, qid, mail->user, mail->domain);
	filter_api_accept_notify(qid);
}

static void
on_rcpt(uint64_t id, uint64_t qid, struct filter_mailaddr *rcpt)
{
	printf("filter: RCPT id=%016"PRIx64", qid=%016"PRIx64" %s@%s\n",
	    id, qid, rcpt->user, rcpt->domain);
	filter_api_accept_notify(qid);
}

static void
on_data(uint64_t id, uint64_t qid)
{
	printf("filter: DATA id=%016"PRIx64", qid=%016"PRIx64"\n", id, qid);
	filter_api_accept_notify(qid);
}

static void
on_dataline(uint64_t id, const char *data)
{
	printf("filter-data: id=%016"PRIx64", \"%s\"\n", id, data);
}

static void
on_eom(uint64_t id, uint64_t qid)
{
	printf("filter-eom: id=%016"PRIx64", qid=%016"PRIx64"\n", id, qid);
	filter_api_accept_notify(qid);
}

int
main(int argc, char **argv)
{
	filter_api_on_event(on_event);
	filter_api_on_notify(on_notify);
	filter_api_on_connect(on_connect);
	filter_api_on_helo(on_helo);
	filter_api_on_mail(on_mail);
	filter_api_on_rcpt(on_rcpt);
	filter_api_on_data(on_data);
	filter_api_on_dataline(on_dataline, 0);
	filter_api_on_eom(on_eom);
	filter_api_loop();
	return (1);
}
