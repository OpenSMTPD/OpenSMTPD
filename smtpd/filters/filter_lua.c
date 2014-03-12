/*	$OpenBSD$	*/

/*
 * Copyright (c) 2013 Eric Faurot <eric@openbsd.org>
 * Copyright (c) 2014 Emmanuel Vadot <manu@bocal.org>
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

#include <sys/types.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

lua_State *L;

static int
l_filter_accept(lua_State *L)
{
	uint64_t	id;
	const char	*s_id;

	if (lua_gettop(L) != 1)
		return (0);

	s_id = luaL_checklstring(L, 1, NULL);
	id = strtoumax(s_id, (char **)NULL, 10);

	filter_api_accept(id);

	return (0);
}

static int
l_filter_reject(lua_State *L)
{
	uint64_t	id;
	const char	*s_id;
	uint32_t	action;

	if (lua_gettop(L) != 2)
		return (0);

	s_id = luaL_checklstring(L, 1, NULL);
	id = strtoumax(s_id, (char **)NULL, 10);
	action = luaL_checkinteger(L, 2);

	switch (action) {
	case FILTER_FAIL:
	case FILTER_CLOSE:
		filter_api_reject(id, action);
		break;
	}

	return (0);
}

static int
l_filter_reject_code(lua_State *L)
{
	uint64_t	id;
	const char	*s_id;
	uint32_t	action;
	uint32_t	code;
	const char	*line;

	if (lua_gettop(L) != 4)
		return (0);

	s_id = luaL_checklstring(L, 1, NULL);
	id = strtoimax(s_id, (char **)NULL, 10);
	action = luaL_checkinteger(L, 2);
	code = luaL_checkinteger(L, 3);
	line = luaL_checklstring(L, 4, NULL);

	switch (action) {
	case FILTER_FAIL:
	case FILTER_CLOSE:
		filter_api_reject_code(id, action, code, line);
		break;
	}

	return (0);
}

static int
l_filter_writeln(lua_State *L)
{
	uint64_t	id;
	const char	*s_id;
	const char	*line;

	if (lua_gettop(L) != 2)
		return (0);

	s_id = luaL_checklstring(L, 1, NULL);
	id = strtoimax(s_id, (char **)NULL, 10);
	line = luaL_checklstring(L, 2, NULL);

	filter_api_writeln(id, line);

	return (0);
}

static const luaL_Reg l_filter [] = {
	{"accept", l_filter_accept},
	{"reject", l_filter_reject},
	{"reject_code", l_filter_reject_code},
	{"writeln", l_filter_writeln},
	{NULL, NULL}
};

static int
on_connect(uint64_t id, struct filter_connect *conn)
{
	char	s_id[20];

	memset(s_id, 0, 20);
	sprintf(s_id, "%lu", id);

	lua_getglobal(L, "on_connect");
	lua_pushstring(L, s_id);
	lua_pushstring(L, filter_api_sockaddr_to_text((struct sockaddr *)&conn->local));
	lua_pushstring(L, filter_api_sockaddr_to_text((struct sockaddr *)&conn->remote));
	lua_pushstring(L, conn->hostname);

	if (lua_pcall(L, 4, 0, 0)) {
		log_warnx("warn: filter-lua: on_connect() failed: %s", lua_tostring(L, -1));
		exit(1);
	}

	return (1);
}

static int
on_helo(uint64_t id, const char *helo)
{
	char	s_id[20];

	memset(s_id, 0, 20);
	sprintf(s_id, "%lu", id);

	lua_getglobal(L, "on_helo");
	lua_pushstring(L, s_id);
	lua_pushstring(L, helo);

	if (lua_pcall(L, 2, 0, 0)) {
		log_warnx("warn: filter-lua: on_helo() failed: %s", lua_tostring(L, -1));
		exit(1);
	}

	return (1);
}

static int
on_mail(uint64_t id, const char *mail)
{
	char	s_id[20];

	memset(s_id, 0, 20);
	sprintf(s_id, "%lu", id);

	lua_getglobal(L, "on_mail");
	lua_pushstring(L, s_id);
	lua_pushstring(L, mail);

	if (lua_pcall(L, 2, 0, 0)) {
		log_warnx("warn: filter-lua: on_mail() failed: %s", lua_tostring(L, -1));
		exit(1);
	}

	return (1);
}

static int
on_rcpt(uint64_t id, const char *rcpt)
{
	char	s_id[20];

	memset(s_id, 0, 20);
	sprintf(s_id, "%lu", id);

	lua_getglobal(L, "on_rcpt");
	lua_pushstring(L, s_id);
	lua_pushstring(L, rcpt);

	if (lua_pcall(L, 2, 0, 0)) {
		log_warnx("warn: filter-lua: on_rcpt() failed: %s", lua_tostring(L, -1));
		exit(1);
	}

	return (1);
}

static int
on_data(uint64_t id)
{
	char	s_id[20];

	memset(s_id, 0, 20);
	sprintf(s_id, "%lu", id);

	lua_getglobal(L, "on_data");
	lua_pushstring(L, s_id);

	if (lua_pcall(L, 1, 0, 0)) {
		log_warnx("warn: filter-lua: on_data() failed: %s", lua_tostring(L, -1));
		exit(1);
	}

	return (1);
}

static int
on_eom(uint64_t id)
{
	char	s_id[20];

	memset(s_id, 0, 20);
	sprintf(s_id, "%lu", id);

	lua_getglobal(L, "on_eom");
	lua_pushstring(L, s_id);

	if (lua_pcall(L, 1, 0, 0)) {
		log_warnx("warn: filter-lua: on_eom() failed: %s", lua_tostring(L, -1));
		exit(1);
	}

	return (1);
}

static void
on_disconnect(uint64_t id)
{
	char	s_id[20];

	memset(s_id, 0, 20);
	sprintf(s_id, "%lu", id);

	lua_getglobal(L, "on_disconnect");
	lua_pushstring(L, s_id);

	if (lua_pcall(L, 1, 0, 0)) {
		log_warnx("warn: filter-lua: on_eom() failed: %s", lua_tostring(L, -1));
		exit(1);
	}
}

int
main(int argc, char **argv)
{
	int	ch;
	const char	*scriptpath = "/tmp/test.lua";

	log_init(-1);

	log_debug("debug: filter-lua: args: %s", argv[1]);
	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			log_warnx("warn: filter-lua: bad option");
			return (1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	log_debug("debug: filter-lua: starting...");

	if ((L = luaL_newstate()) == NULL) {
		log_warnx("warn: filter-lua: can't create lua state");
		return (1);
	}
	luaL_openlibs(L);
	luaL_newlib(L, l_filter);
	luaL_newmetatable(L, "filter");
	lua_setmetatable(L, -2);

	lua_pushnumber(L, FILTER_OK);
	lua_setfield(L, -2, "FILTER_OK");
	lua_pushnumber(L, FILTER_FAIL);
	lua_setfield(L, -2, "FILTER_FAIL");
	lua_pushnumber(L, FILTER_CLOSE);
	lua_setfield(L, -2, "FILTER_CLOSE");

	lua_setglobal(L, "filter");

	if (luaL_loadfile(L, scriptpath) != 0) {
		log_warnx("warn: filter-lua: error loading script: %s", scriptpath);
		return (1);
	}

	if (lua_pcall(L, 0, 0, 0)) {
		log_warnx("warn: filter-lua: error running script: %s", scriptpath);
		return (1);
	}

	lua_getglobal(L, "on_connect");
	if (lua_isfunction(L, 1)) {
		log_debug("debug: filter-lua: on_connect is present");
		filter_api_on_connect(on_connect);
	}
	lua_getglobal(L, "on_helo");
	if (lua_isfunction(L, 1)) {
		log_debug("debug: filter-lua: on_helo is present");
		filter_api_on_helo(on_helo);
	}
	lua_getglobal(L, "on_mail");
	if (lua_isfunction(L, 1)) {
		log_debug("debug: filter-lua: on_mail is present");
		filter_api_on_mail(on_mail);
	}
	lua_getglobal(L, "on_rcpt");
	if (lua_isfunction(L, 1)) {
		log_debug("debug: filter-lua: on_rcpt is present");
		filter_api_on_rcpt(on_rcpt);
	}
	lua_getglobal(L, "on_data");
	if (lua_isfunction(L, 1)) {
		log_debug("debug: filter-lua: on_data is present");
		filter_api_on_data(on_data);
	}
	lua_getglobal(L, "on_eom");
	if (lua_isfunction(L, 1)) {
		log_debug("debug: filter-lua: on_eom is present");
		filter_api_on_eom(on_eom);
	}

	filter_api_loop();

	log_debug("debug: filter-lua: exiting");

	return (0);
}
