/*      $OpenBSD$   */

/*
 * Copyright (c) 2014 Eric Faurot <eric@openbsd.org>
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

#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

#include <Python.h>

#include "smtpd-defines.h"
#include "smtpd-api.h"
#include "log.h"

static PyObject *py_on_init;
static PyObject *py_on_insert;
static PyObject *py_on_commit;
static PyObject *py_on_rollback;
static PyObject *py_on_update;
static PyObject *py_on_delete;
static PyObject *py_on_hold;
static PyObject *py_on_release;
static PyObject *py_on_batch;
static PyObject *py_on_messages;
static PyObject *py_on_envelopes;
static PyObject *py_on_schedule;
static PyObject *py_on_remove;
static PyObject *py_on_suspend;
static PyObject *py_on_resume;

static void
check_err(const char *name)
{
	if (PyErr_Occurred()) {
		PyErr_Print();
		fatalx("warn: scheduler-python: error in %s handler", name);
	}
}

static PyObject *
dispatch(PyObject *handler, PyObject *args)
{
	PyObject *ret;

	ret = PyObject_CallObject(handler, args);
	Py_DECREF(args);

	if (PyErr_Occurred()) {
		PyErr_Print();
		fatalx("warn: scheduler-python: exception");
	}

	return (ret);
}



static int
get_int(PyObject *o)
{
	if (PyLong_Check(o))
		return (PyLong_AsLong(o));
	if (PyInt_Check(o))
		return (PyInt_AsLong(o));

	PyErr_SetString(PyExc_TypeError, "int type expected");
	return (0);
}

static size_t
get_size_t(PyObject *o)
{
	if (PyLong_Check(o))
		return (PyLong_AsUnsignedLongLong(o));
	if (PyInt_Check(o))
		return (PyInt_AsUnsignedLongLongMask(o));

	PyErr_SetString(PyExc_TypeError, "int type expected");
	return (0);
}

static size_t
get_uint32_t(PyObject *o)
{
	if (PyLong_Check(o))
		return (PyLong_AsUnsignedLong(o));
	if (PyInt_Check(o))
		return (PyInt_AsUnsignedLongMask(o));

	PyErr_SetString(PyExc_TypeError, "int type expected");
	return (0);
}

static time_t
get_time_t(PyObject *o)
{
	if (PyLong_Check(o))
		return (PyLong_AsUnsignedLongLong(o));
	if (PyInt_Check(o))
		return (PyInt_AsUnsignedLongLongMask(o));

	PyErr_SetString(PyExc_TypeError, "int type expected");
	return (0);
}

static int
scheduler_python_init(void)
{
	PyObject *py_ret;
	int r;

	py_ret = dispatch(py_on_init, PyTuple_New(0));

	r = get_int(py_ret);
	Py_DECREF(py_ret);

	check_err("init");
	return (r);
}

static int
scheduler_python_insert(struct scheduler_info *info)
{
	PyObject *py_ret;
	int r;

	py_ret = dispatch(py_on_insert, Py_BuildValue("KllLLLLL",
	    (unsigned long long)info->evpid,
	    (long)info->type,
	    (long)info->retry,
	    (long long)info->creation,
	    (long long)info->expire,
	    (long long)info->lasttry,
	    (long long)info->lastbounce,
	    (long long)info->nexttry));

	r = get_int(py_ret);
	Py_DECREF(py_ret);

	check_err("insert");
	return (r);
}

static size_t
scheduler_python_commit(uint32_t msgid)
{
	PyObject *py_ret;
	size_t r;

	py_ret = dispatch(py_on_commit, Py_BuildValue("(k)",
	    (unsigned long)msgid));

	r = get_size_t(py_ret);
	Py_DECREF(py_ret);

	check_err("commit");
	return (r);
}

static size_t
scheduler_python_rollback(uint32_t msgid)
{
	PyObject *py_ret;
	size_t r;

	py_ret = dispatch(py_on_rollback, Py_BuildValue("(k)",
	    (unsigned long)msgid));

	r = get_size_t(py_ret);
	Py_DECREF(py_ret);

	check_err("rollback");
	return (r);
}

static int
scheduler_python_update(struct scheduler_info *info)
{
	PyObject *py_ret;
	time_t nexttry;

	py_ret = dispatch(py_on_update, Py_BuildValue("KllLLLLL",
	    (unsigned long long)info->evpid,
	    (long)info->type,
	    (long)info->retry,
	    (long long)info->creation,
	    (long long)info->expire,
	    (long long)info->lasttry,
	    (long long)info->lastbounce,
	    (long long)info->nexttry));

	nexttry = get_time_t(py_ret);
	Py_DECREF(py_ret);
	check_err("update");

	if (nexttry == -1)
		return (-1);
	if (nexttry == 0)
		return (0);

	info->nexttry = nexttry;
	return (1);
}

static int
scheduler_python_delete(uint64_t evpid)
{
	PyObject *py_ret;
	int r;

	py_ret = dispatch(py_on_delete, Py_BuildValue("(K)",
	    (unsigned long long)evpid));

	r = get_int(py_ret);
	Py_DECREF(py_ret);

	check_err("delete");
	return (r);
}

static int
scheduler_python_hold(uint64_t evpid, uint64_t holdq)
{
	PyObject *py_ret;
	int r;

	py_ret = dispatch(py_on_hold, Py_BuildValue("KK",
	    (unsigned long long)evpid,
	    (unsigned long long)holdq));

	r = get_int(py_ret);
	Py_DECREF(py_ret);

	check_err("hold");
	return (r);
}

static int
scheduler_python_release(int type, uint64_t holdq, int count)
{
	PyObject *py_ret;
	int r;

	py_ret = dispatch(py_on_release, Py_BuildValue("lKl",
	    (long)type,
	    (unsigned long long)holdq,
	    (long)count));

	r = get_int(py_ret);
	Py_DECREF(py_ret);

	check_err("release");
	return (r);
}

static int
scheduler_python_batch(int mask, int *delay, size_t *count, uint64_t *evpids, int *types)
{
	PyObject *py_ret, *o;
	int type;
	unsigned long long evpid;
	size_t n, i;
	ssize_t r;

	n = *count;

	py_ret = dispatch(py_on_batch,  Py_BuildValue("lK",
	    (long)mask,
	    (unsigned long long)n));

	if (PyInt_Check(py_ret)) {
		*delay = PyInt_AsLong(py_ret);
		*count = 0;
		Py_DECREF(py_ret);
		return (0);
	}
	if (PyLong_Check(py_ret)) {
		*delay = PyLong_AsLong(py_ret);
		*count = 0;
		Py_DECREF(py_ret);
		return (0);
	}

	*delay = 0;
	r = PySequence_Length(py_ret);

	check_err("batch1");

	if (r <= 0 || (size_t)r > n)
		fatalx("bad length");

	for (i = 0; i < (size_t)r; i++) {
		o = PySequence_GetItem(py_ret, i);
		PyArg_ParseTuple(o, "Ki", &evpid, &type);
		evpids[i] = evpid;
		types[i] = type;
		Py_DECREF(o);
	}

	Py_DECREF(py_ret);

	check_err("batch");

	return (1);
}

static size_t
scheduler_python_messages(uint32_t msgid, uint32_t *dst, size_t sz)
{
	PyObject *py_ret, *o;
	ssize_t r;
	size_t i;

	py_ret = dispatch(py_on_messages, Py_BuildValue("kK",
	    (unsigned long)msgid,
	    (unsigned long long)sz));

	r = PySequence_Length(py_ret);

	if (r < 0 || (size_t)r > sz)
		fatalx("bad length");

	for (i = 0; i < (size_t)r; i++) {
		o = PySequence_ITEM(py_ret, i);
		dst[i] = get_uint32_t(o);
		Py_DECREF(o);
	}

	Py_DECREF(py_ret);

	check_err("messages");

	return (r);
}

static size_t
scheduler_python_envelopes(uint64_t evpid, struct evpstate *dst, size_t sz)
{
	PyObject *py_ret, *o;
	unsigned int flags, retry;
	unsigned long long tevpid;
	long long timestamp;
	ssize_t r;
	size_t i;

	py_ret = dispatch(py_on_envelopes, Py_BuildValue("KK",
	    (unsigned long long)evpid,
	    (unsigned long long)sz));

	check_err("envelopes");

	r = PySequence_Length(py_ret);

	if (r < 0 || (size_t)r > sz)
		fatalx("bad length");

	check_err("envelopes");

	for (i = 0; i < (size_t)r; i++) {
		o = PySequence_ITEM(py_ret, i);

		check_err("envelopes");

		PyArg_ParseTuple(o, "KIIL", &tevpid, &flags, &retry, &timestamp);
		check_err("envelopes");

		dst[i].evpid = tevpid;
		dst[i].flags = flags;
		dst[i].retry = retry;
		dst[i].time = timestamp;

		check_err("envelopes");

		Py_DECREF(o);
	}

	Py_DECREF(py_ret);

	check_err("envelopes");

	return (r);
}

static int
scheduler_python_schedule(uint64_t evpid)
{
	PyObject *py_ret;
	int r;

	py_ret = dispatch(py_on_schedule, Py_BuildValue("(K)",
	    (unsigned long long)evpid));

	r = get_int(py_ret);
	Py_DECREF(py_ret);

	check_err("schedule");
	return (r);
}

static int
scheduler_python_remove(uint64_t evpid)
{
	PyObject *py_ret;
	int r;

	py_ret = dispatch(py_on_remove, Py_BuildValue("(K)",
	    (unsigned long long)evpid));

	r = get_int(py_ret);
	Py_DECREF(py_ret);

	check_err("remove");
	return (r);
}

static int
scheduler_python_suspend(uint64_t evpid)
{
	PyObject *py_ret;
	int r;

	py_ret = dispatch(py_on_suspend, Py_BuildValue("(K)",
	    (unsigned long long)evpid));

	r = get_int(py_ret);
	Py_DECREF(py_ret);

	check_err("suspend");
	return (r);
}

static int
scheduler_python_resume(uint64_t evpid)
{
	PyObject *py_ret;
	int r;

	py_ret = dispatch(py_on_resume, Py_BuildValue("(K)",
	    (unsigned long long)evpid));

	r = get_int(py_ret);
	Py_DECREF(py_ret);

	check_err("resume");
	return (r);
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

static PyMethodDef py_methods[] = {
	{ NULL, NULL, 0, NULL }
};

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
			log_warnx("warn: scheduler-python: bad option");
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
	self = Py_InitModule("scheduler", py_methods);

	PyModule_AddIntConstant(self, "SCHED_REMOVE", SCHED_REMOVE);
	PyModule_AddIntConstant(self, "SCHED_EXPIRE", SCHED_EXPIRE);
	PyModule_AddIntConstant(self, "SCHED_UPDATE", SCHED_UPDATE);
	PyModule_AddIntConstant(self, "SCHED_BOUNCE", SCHED_BOUNCE);
	PyModule_AddIntConstant(self, "SCHED_MDA", SCHED_MDA);
	PyModule_AddIntConstant(self, "SCHED_MTA", SCHED_MTA);

	PyModule_AddIntConstant(self, "D_BOUNCE", D_BOUNCE);
	PyModule_AddIntConstant(self, "D_MDA", D_MDA);
	PyModule_AddIntConstant(self, "D_MTA", D_MTA);

	PyModule_AddIntConstant(self, "EF_PENDING", EF_PENDING);
	PyModule_AddIntConstant(self, "EF_INFLIGHT", EF_INFLIGHT);
	PyModule_AddIntConstant(self, "EF_SUSPEND", EF_SUSPEND);
	PyModule_AddIntConstant(self, "EF_HOLD", EF_HOLD);

	buf = loadfile(path);
	code = Py_CompileString(buf, path, Py_file_input);
	free(buf);

	if (code == NULL) {
		PyErr_Print();
		log_warnx("warn: scheduler-python: failed to compile %s", path);
		return (1);
	}

	module = PyImport_ExecCodeModuleEx("myscheduler", code, path);

	if (module == NULL) {
		PyErr_Print();
		log_warnx("warn: scheduler-python: failed to install module %s", path);
		return (1);
	}

	log_debug("debug: scheduler-python: starting...");

	py_on_init = PyObject_GetAttrString(module, "scheduler_init");
	py_on_insert = PyObject_GetAttrString(module, "scheduler_insert");
	py_on_commit = PyObject_GetAttrString(module, "scheduler_commit");
	py_on_rollback = PyObject_GetAttrString(module, "scheduler_rollback");
	py_on_update = PyObject_GetAttrString(module, "scheduler_update");
	py_on_delete = PyObject_GetAttrString(module, "scheduler_delete");
	py_on_hold = PyObject_GetAttrString(module, "scheduler_hold");
	py_on_release = PyObject_GetAttrString(module, "scheduler_release");
	py_on_batch = PyObject_GetAttrString(module, "scheduler_batch");
	py_on_messages = PyObject_GetAttrString(module, "scheduler_messages");
	py_on_envelopes = PyObject_GetAttrString(module, "scheduler_envelopes");
	py_on_schedule = PyObject_GetAttrString(module, "scheduler_schedule");
	py_on_remove = PyObject_GetAttrString(module, "scheduler_remove");
	py_on_suspend = PyObject_GetAttrString(module, "scheduler_suspend");
	py_on_resume = PyObject_GetAttrString(module, "scheduler_resume");

	scheduler_api_on_init(scheduler_python_init);
	scheduler_api_on_insert(scheduler_python_insert);
	scheduler_api_on_commit(scheduler_python_commit);
	scheduler_api_on_rollback(scheduler_python_rollback);
	scheduler_api_on_update(scheduler_python_update);
	scheduler_api_on_delete(scheduler_python_delete);
	scheduler_api_on_hold(scheduler_python_hold);
	scheduler_api_on_release(scheduler_python_release);
	scheduler_api_on_batch(scheduler_python_batch);
	scheduler_api_on_messages(scheduler_python_messages);
	scheduler_api_on_envelopes(scheduler_python_envelopes);
	scheduler_api_on_schedule(scheduler_python_schedule);
	scheduler_api_on_remove(scheduler_python_remove);
	scheduler_api_on_suspend(scheduler_python_suspend);
	scheduler_api_on_resume(scheduler_python_resume);

	scheduler_api_no_chroot();
	scheduler_api_dispatch();

	log_debug("debug: scheduler-python: exiting");
	Py_Finalize();

	return (1);
}
