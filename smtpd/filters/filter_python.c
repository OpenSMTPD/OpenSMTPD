/*      $OpenBSD$   */

/*
 * Copyright (c) 2014 Gilles Chehade <gilles@poolp.org>
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
#include <sys/socket.h>

#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

#include <Python.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

static PyObject	*py_on_connect;
static PyObject	*py_on_helo;
static PyObject	*py_on_mail;
static PyObject	*py_on_rcpt;
static PyObject	*py_on_data;
static PyObject	*py_on_eom;
static PyObject	*py_on_dataline;

static PyObject	*py_on_commit;
static PyObject	*py_on_rollback;
static PyObject	*py_on_disconnect;


static PyObject *
py_filter_accept(PyObject *self, PyObject *args)
{
	uint64_t	id;

	if (! PyArg_ParseTuple(args, "K", &id))
		return NULL;
	filter_api_accept(id);
	Py_RETURN_TRUE;
}

static PyObject *
py_filter_reject(PyObject *self, PyObject *args)
{
	uint64_t	id;
	uint32_t	action;

	if (! PyArg_ParseTuple(args, "Ki", &id, &action))
		return NULL;

	switch (action) {
	case FILTER_FAIL:
	case FILTER_CLOSE:
		filter_api_reject(id, action);
		Py_RETURN_TRUE;
		break;
	}
	Py_RETURN_FALSE;
}

static PyObject *
py_filter_reject_code(PyObject *self, PyObject *args)
{
	uint64_t	id;
	uint32_t	action;
	uint32_t	code;
	const char    *line;

	if (! PyArg_ParseTuple(args, "Kiis", &id, &action, &code, &line))
		return NULL;

	switch (action) {
	case FILTER_FAIL:
	case FILTER_CLOSE:
		filter_api_reject_code(id, action, code, line);
		Py_RETURN_TRUE;
		break;
	}
	Py_RETURN_FALSE;
}

static PyObject *
py_filter_writeln(PyObject *self, PyObject *args)
{
	uint64_t	id;
	const char     *line;

	if (! PyArg_ParseTuple(args, "Ks", &id, &line))
		return NULL;
	filter_api_writeln(id, line);
	Py_RETURN_TRUE;
}

static PyMethodDef py_methods[] = {
	{ "accept", py_filter_accept, METH_VARARGS, "accept" },
	{ "reject", py_filter_reject, METH_VARARGS, "reject" },
	{ "reject_code", py_filter_reject_code, METH_VARARGS, "reject_code" },
	{ "writeln", py_filter_writeln, METH_VARARGS, "writeln" },
	{ NULL, NULL, 0, NULL }
};


static int
on_connect(uint64_t id, struct filter_connect *conn)
{
	PyObject *py_args;
	PyObject *py_ret;
	PyObject *py_id;
	PyObject *py_local;
	PyObject *py_remote;
	PyObject *py_hostname;

	py_args     = PyTuple_New(4);
	py_id       = PyLong_FromUnsignedLongLong(id);
	py_local    = PyString_FromString(filter_api_sockaddr_to_text((struct sockaddr *)&conn->local));
	py_remote   = PyString_FromString(filter_api_sockaddr_to_text((struct sockaddr *)&conn->remote));
	py_hostname = PyString_FromString(conn->hostname);

	PyTuple_SetItem(py_args, 0, py_id);
	PyTuple_SetItem(py_args, 1, py_local);
	PyTuple_SetItem(py_args, 2, py_remote);
	PyTuple_SetItem(py_args, 3, py_hostname);

	py_ret = PyObject_CallObject(py_on_connect, py_args);
	Py_DECREF(py_args);

	if (py_ret == NULL) {
		PyErr_Print();
		log_warnx("warn: filter-python: call to on_connect handler failed");
		exit(1);
	}

	return (1);
}

static int
on_helo(uint64_t id, const char *helo)
{
	PyObject *py_args;
	PyObject *py_ret;
	PyObject *py_id;
	PyObject *py_helo;

	py_args = PyTuple_New(2);
	py_id   = PyLong_FromUnsignedLongLong(id);
	py_helo = PyString_FromString(helo);

	PyTuple_SetItem(py_args, 0, py_id);
	PyTuple_SetItem(py_args, 1, py_helo);

	py_ret = PyObject_CallObject(py_on_helo, py_args);
	Py_DECREF(py_args);
	if (py_ret == NULL) {
		PyErr_Print();
		log_warnx("warn: filter-python: call to on_helo handler failed");
		exit(1);
	}
	return 1;
}

static int
on_mail(uint64_t id, struct mailaddr *mail)
{
	PyObject *py_args;
	PyObject *py_ret;
	PyObject *py_id;
	PyObject *py_sender;

	py_args   = PyTuple_New(2);
	py_id     = PyLong_FromUnsignedLongLong(id);
	py_sender = PyString_FromString(filter_api_mailaddr_to_text(mail));

	PyTuple_SetItem(py_args, 0, py_id);
	PyTuple_SetItem(py_args, 1, py_sender);

	py_ret = PyObject_CallObject(py_on_mail, py_args);
	Py_DECREF(py_args);

	if (py_ret == NULL) {
		PyErr_Print();
		log_warnx("warn: filter-python: call to on_mail handler failed");
		exit(1);
	}

	return (1);
}

static int
on_rcpt(uint64_t id, struct mailaddr *rcpt)
{
	PyObject *py_args;
	PyObject *py_ret;
	PyObject *py_id;
	PyObject *py_rcpt;

	py_args  = PyTuple_New(2);
	py_id    = PyLong_FromUnsignedLongLong(id);
	py_rcpt  = PyString_FromString(filter_api_mailaddr_to_text(rcpt));

	PyTuple_SetItem(py_args, 0, py_id);
	PyTuple_SetItem(py_args, 1, py_rcpt);

	py_ret = PyObject_CallObject(py_on_rcpt, py_args);
	Py_DECREF(py_args);

	if (py_ret == NULL) {
		PyErr_Print();
		log_warnx("warn: filter-python: call to on_rcpt handler failed");
		exit(1);
	}

	return (1);
}

static int
on_data(uint64_t id)
{
	PyObject *py_args;
	PyObject *py_ret;
	PyObject *py_id;

	py_args = PyTuple_New(1);
	py_id   = PyLong_FromUnsignedLongLong(id);
	PyTuple_SetItem(py_args, 0, py_id);
	py_ret = PyObject_CallObject(py_on_data, py_args);
	Py_DECREF(py_args);

	if (py_ret == NULL) {
		PyErr_Print();
		log_warnx("warn: filter-python: call to on_datra handler failed");
		exit(1);
	}

	return (1);
}

static int
on_eom(uint64_t id, size_t sz)
{
	PyObject *py_args;
	PyObject *py_ret;
	PyObject *py_id;
	PyObject *py_sz;

	py_args = PyTuple_New(2);
	py_id   = PyLong_FromUnsignedLongLong(id);
	py_sz   = PyLong_FromSize_t(sz);
	PyTuple_SetItem(py_args, 0, py_id);
	PyTuple_SetItem(py_args, 1, py_sz);
	py_ret = PyObject_CallObject(py_on_eom, py_args);
	Py_DECREF(py_args);

	if (py_ret == NULL) {
		PyErr_Print();
		log_warnx("warn: filter-python: call to on_eom handler failed");
		exit(1);
	}

	return (1);
}

static void
on_commit(uint64_t id)
{
	PyObject *py_args;
	PyObject *py_ret;
	PyObject *py_id;

	py_args = PyTuple_New(1);
	py_id   = PyLong_FromUnsignedLongLong(id);
	PyTuple_SetItem(py_args, 0, py_id);
	py_ret = PyObject_CallObject(py_on_commit, py_args);
	Py_DECREF(py_args);

	if (py_ret == NULL) {
		PyErr_Print();
		log_warnx("warn: filter-python: call to on_commit handler failed");
		exit(1);
	}
}

static void
on_rollback(uint64_t id)
{
	PyObject *py_args;
	PyObject *py_ret;
	PyObject *py_id;

	py_args = PyTuple_New(1);
	py_id   = PyLong_FromUnsignedLongLong(id);
	PyTuple_SetItem(py_args, 0, py_id);
	py_ret = PyObject_CallObject(py_on_rollback, py_args);
	Py_DECREF(py_args);

	if (py_ret == NULL) {
		PyErr_Print();
		log_warnx("warn: filter-python: call to on_rollback handler failed");
		exit(1);
	}
}

static void
on_disconnect(uint64_t id)
{
	PyObject *py_args;
	PyObject *py_ret;
	PyObject *py_id;

	py_args = PyTuple_New(1);
	py_id   = PyLong_FromUnsignedLongLong(id);
	PyTuple_SetItem(py_args, 0, py_id);
	py_ret = PyObject_CallObject(py_on_disconnect, py_args);
	Py_DECREF(py_args);

	if (py_ret == NULL) {
		PyErr_Print();
		log_warnx("warn: filter-python: call to on_disconnect handler failed");
		exit(1);
	}
}

static void
on_dataline(uint64_t id, const char *line)
{
	PyObject *py_args;
	PyObject *py_ret;
	PyObject *py_id;
	PyObject *py_line;

	py_args = PyTuple_New(2);
	py_id   = PyLong_FromUnsignedLongLong(id);
	py_line = PyString_FromString(line);

	PyTuple_SetItem(py_args, 0, py_id);
	PyTuple_SetItem(py_args, 1, py_line);

	py_ret = PyObject_CallObject(py_on_dataline, py_args);
	Py_DECREF(py_args);

	if (py_ret == NULL) {
		PyErr_Print();
		log_warnx("warn: filter-python: call to on_dataline handler failed");
		exit(1);
	}
}

static char *
loadfile(const char * path)
{
	FILE	*f;
	off_t	 oz;
	size_t	 sz;
	char	*buf;

	if ((f = fopen(path, "r")) == NULL)
		err(1, "fopen");

	if (fseek(f, 0, SEEK_END) == -1)
		err(1, "fseek");

	oz = ftello(f);

	if (fseek(f, 0, SEEK_SET) == -1)
		err(1, "fseek");

	if (oz >= SIZE_MAX)
		errx(1, "too big");

	sz = oz;

	if ((buf = malloc(sz + 1)) == NULL)
		err(1, "malloc");

	if (fread(buf, 1, sz, f) != sz)
		err(1, "fread");

	buf[sz] = '\0';

	fclose(f);

	return (buf);
}

int
main(int argc, char **argv)
{
	int		 ch;
	char		*path;
	char		*buf;
	PyObject	*self, *code, *module;

	log_init(-1);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			log_warnx("warn: filter-python: bad option");
			return (1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		errx(1, "missing path");
	path = argv[0];

	Py_Initialize();
	self = Py_InitModule("filter", py_methods);
	PyModule_AddIntConstant(self, "FILTER_OK", FILTER_OK);
	PyModule_AddIntConstant(self, "FILTER_FAIL", FILTER_FAIL);
	PyModule_AddIntConstant(self, "FILTER_CLOSE", FILTER_CLOSE);

	buf = loadfile(path);
	code = Py_CompileString(buf, path, Py_file_input);
	free(buf);

	if (code == NULL) {
		PyErr_Print();
		log_warnx("warn: filter-python: failed to compile %s", path);
		return (1);
	}

	module = PyImport_ExecCodeModuleEx("myfilter", code, path);

	if (module == NULL) {
		PyErr_Print();
		log_warnx("warn: filter-python: failed to install module %s", path);
		return (1);
	}

	log_debug("debug: filter-python: starting...");

	filter_api_on_connect(on_connect);

	py_on_connect = PyObject_GetAttrString(module, "on_connect");
	if (py_on_connect && PyCallable_Check(py_on_connect))
		filter_api_on_connect(on_connect);

	py_on_helo = PyObject_GetAttrString(module, "on_helo");
	if (py_on_helo && PyCallable_Check(py_on_helo))
		filter_api_on_helo(on_helo);

	py_on_mail = PyObject_GetAttrString(module, "on_mail");
	if (py_on_mail && PyCallable_Check(py_on_mail))
		filter_api_on_mail(on_mail);

	py_on_rcpt = PyObject_GetAttrString(module, "on_rcpt");
	if (py_on_rcpt && PyCallable_Check(py_on_rcpt))
		filter_api_on_rcpt(on_rcpt);

	py_on_data = PyObject_GetAttrString(module, "on_data");
	if (py_on_data && PyCallable_Check(py_on_data))
		filter_api_on_data(on_data);

	py_on_eom = PyObject_GetAttrString(module, "on_eom");
	if (py_on_eom && PyCallable_Check(py_on_eom))
		filter_api_on_eom(on_eom);

	py_on_commit = PyObject_GetAttrString(module, "on_commit");
	if (py_on_commit && PyCallable_Check(py_on_commit))
		filter_api_on_commit(on_commit);

	py_on_rollback = PyObject_GetAttrString(module, "on_rollback");
	if (py_on_rollback && PyCallable_Check(py_on_rollback))
		filter_api_on_rollback(on_rollback);

	py_on_dataline = PyObject_GetAttrString(module, "on_dataline");
	if (py_on_dataline && PyCallable_Check(py_on_dataline))
		filter_api_on_dataline(on_dataline);

	py_on_disconnect = PyObject_GetAttrString(module, "on_disconnect");
	if (py_on_disconnect && PyCallable_Check(py_on_disconnect))
		filter_api_on_disconnect(on_disconnect);

	filter_api_loop();

	log_debug("debug: filter-python: exiting");
	Py_Finalize();

	return (1);
}
