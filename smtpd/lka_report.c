/*	$OpenBSD$	*/

/*
 * Copyright (c) 2018 Gilles Chehade <gilles@poolp.org>
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smtpd.h"
#include "log.h"


void
lka_report_smtp_link_connect(time_t tm, uint64_t reqid, const char *src_addr, const char *dest_addr)
{
	log_debug("SMTP LINK CONNECT: %s->%s", src_addr, dest_addr);
}

void
lka_report_smtp_link_disconnect(time_t tm, uint64_t reqid, const char *src_addr, const char *dest_addr)
{
	log_debug("SMTP LINK DISCONNECT: %s->%s", src_addr, dest_addr);
}

void
lka_report_smtp_tx_begin(time_t tm, uint64_t reqid)
{
	log_debug("SMTP TX BEGIN");
}

void
lka_report_smtp_tx_commit(time_t tm, uint64_t reqid)
{
	log_debug("SMTP TX COMMIT");
}

void
lka_report_smtp_tx_rollback(time_t tm, uint64_t reqid)
{
	log_debug("SMTP TX ROLLBACK");
}

void
lka_report_smtp_protocol_client(time_t tm, uint64_t reqid, const char *command)
{
	log_debug("SMTP CLIENT PROTOCOL: %s", command);
}

void
lka_report_smtp_protocol_server(time_t tm, uint64_t reqid, const char *response)
{
	log_debug("SMTP SERVER PROTOCOL: %s", response);
}
