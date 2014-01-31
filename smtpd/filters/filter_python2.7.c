/*      $OpenBSD$   */

/*
 * Copyright (c) 2013 Eric Faurot <eric@openbsd.org>
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

static void
on_connect(uint64_t id, struct filter_connect *conn)
{
	filter_api_accept(id);
}

static void
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
		log_warnx("warn: filter-python2.7: call to on_helo handler failed");
		exit(1);
	}

	filter_api_accept(id);
}

static void
on_mail(uint64_t id, struct mailaddr *mail)
{
	filter_api_accept(id);
}

static void
on_rcpt(uint64_t id, struct mailaddr *rcpt)
{
	filter_api_accept(id);
}

static void
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
		log_warnx("warn: filter-python2.7: call to on_datra handler failed");
		exit(1);
	}

	log_warnx("warn: filter-python2.7: GOT DATA");

	filter_api_accept(id);
}

static void
on_eom(uint64_t id)
{
	PyObject *py_args;
	PyObject *py_ret;
	PyObject *py_id;

	py_args = PyTuple_New(1);
	py_id   = PyLong_FromUnsignedLongLong(id);
	PyTuple_SetItem(py_args, 0, py_id);
	py_ret = PyObject_CallObject(py_on_eom, py_args);
	Py_DECREF(py_args);

	if (py_ret == NULL) {
		PyErr_Print();
		log_warnx("warn: filter-python2.7: call to on_eom handler failed");
		exit(1);
	}

	log_warnx("warn: filter-python2.7: GOT EOM");

	filter_api_accept(id);
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
		log_warnx("warn: filter-python2.7: call to on_dataline handler failed");
		exit(1);
	}

	filter_api_writeln(id, line);
}

int
main(int argc, char **argv)
{
	int	ch;
	const char	*scriptpath = "/tmp/test.py";
	PyObject	*name;
	PyObject	*module;

	log_init(-1);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			log_warnx("warn: filter-python2.7: bad option");
			return (1);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	setenv("PYTHONPATH", "/tmp", 1);
	Py_Initialize();
	name   = PyString_FromString("test");
	module = PyImport_Import(name);
	Py_DECREF(name);

	if (module == NULL) {
		PyErr_Print();
		log_warnx("warn: filter-python2.7: failed to load %s", scriptpath);
		return 1;
	}

	log_debug("debug: filter-python2.7: starting...");

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

	py_on_dataline = PyObject_GetAttrString(module, "on_dataline");
	if (py_on_dataline && PyCallable_Check(py_on_dataline))
		filter_api_on_dataline(on_dataline);

	filter_api_loop();

	log_debug("debug: filter-python2.7: exiting");
	Py_Finalize();

	return (1);
}
