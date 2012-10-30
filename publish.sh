#! /bin/sh
#

CURDIR=`pwd`
FILES=$CURDIR/files

COMMAND=$1
BRANCH=`git branch | grep '* ' | sed 's/* //g'`

# supported commands
case $COMMAND in
    tarball|snapshot|release)
	;;
    *)
	echo "usage: `basename $0` tarball|snapshot|release" >&2
	exit 1;
esac

# supported branches
case $BRANCH in
    master|portable)
	;;
    *)
	echo "`basename $0` $COMMAND not supported on branch $BRANCH" >&2
	exit 1;
esac


# builds a tarball from current branch and returns its name
#
build_tarball()
{
    V=5.2.x
    P=p1
    ASRSRC=/usr/src/lib/libc/asr
    ASRFILES="asr.c asr_debug.c asr_utils.c gethostnamadr_async.c
	      res_send_async.c getaddrinfo_async.c getnameinfo_async.c
	      asr.h asr_private.h"

    T=`mktemp -d /tmp/publish.XXXXXXXXXX` || {
	echo "error: failed to mktemp" >&2
	exit 1
    }
    CURDIR=`pwd`
    if test "$1" = "master"; then
	TARGET=opensmtpd-${V}
	git archive --format=tar --prefix=${TARGET}/ master:smtpd/ | \
	    (cd ${T} && tar xf -)
	for i in ${ASRFILES}; do cp ${ASRSRC}/$i ${T}/${TARGET}/; done
	cat ${T}/${TARGET}/smtpd/Makefile |	\
	    sed 's/-I\/usr\/src\/lib\/libc\/asr//' |	\
	    sed 's/\/usr\/src\/lib\/libc\/asr//' > ${T}/_makefile
	cat ${T}/_makefile > ${T}/${TARGET}/smtpd/Makefile
    else
	TARGET=opensmtpd-${V}${P}
	git archive --format=tar --prefix=${TARGET}/ portable | \
	    (cd ${T} && tar xf -)
	rm -f ${T}/${TARGET}/Makefile ${T}/${TARGET}/smtpd/Makefile
    fi
    (cd ${T} && tar cfz ${FILES}/${TARGET}.tar.gz ${TARGET})
    rm -rf ${T}
    echo ${TARGET}.tar.gz
}

# called for `publish tarball`
#
tarball()
{
    TARBALL=`build_tarball ${1}`
    echo "built master tarball: ${TARBALL}"
}

# called for `publish snapshot`
#
snapshot()
{
    TARBALL=`build_tarball ${1}`
    SNAPSHOT=opensmtpd-`date +%Y%m%d%H%M%S`
    if test "${1}" = "portable"; then
	SNAPSHOT=${SNAPSHOT}p1
    fi
    git tag ${SNAPSHOT}
    mv ${FILES}/${TARBALL} ${FILES}/${SNAPSHOT}.tar.gz

    if test "${1}" = "master"; then
	LASTTAGS=`git tag |grep '^opensmtpd-[0-9]*' | grep -v '[0-9]p[0-9]$' | tail -2 | tr '\n' '@' | sed 's/@$//g'| sed 's/@/../g'`
    else
	LASTTAGS=`git tag |grep '^opensmtpd-[0-9]*' | grep '[0-9]p[0-9]$' | tail -2 | tr '\n' '@' | sed 's/@$//g'| sed 's/@/../g'`
    fi

    CHANGELOG=`git log $LASTTAGS`
    if test "${CHANGELOG}" = ""; then
	echo "Error: nothing new in this snapshot, I won't publish it !" >&2
	git tag -d ${SNAPSHOT}
	exit 1
    fi

    scp -pr ${FILES}/${SNAPSHOT}.tar.gz ssh.poolp.org:/var/nginx/virtual/org.opensmtpd/archives/
    if test $? != 0; then
	echo "Error: could not publish snapshot !" >&2
	git tag -d ${SNAPSHOT}
	exit 1
    fi

    TMP=`mktemp /tmp/publish.XXXXXXXX` || {
	echo "error: mktemp failed" >&2
	git tag -d ${SNAPSHOT}
	exit 1
    }

    cat <<EOF > ${TMP}
User `whoami` has just rebuilt a ${1} snapshot,
available from:

        http://www.OpenSMTPD.org/archives/${SNAPSHOT}.tar.gz

A summary of the content of this snapshot is available below.

Please test and let us know if it breaks something!

If this snapshot doesn't work, please also test with a previous one,
to help us spot where the issue is comming from. You can access all
previous snapshots here:

        http://www.opensmtpd.org/archives/

The OpenSMTPD team ;-)


Summary of changes since last snapshot:
---------------------------------------
${CHANGELOG}
EOF
    ${EDITOR} ${TMP}

    if test $? != 0; then
	rm ${TMP}
	echo "Error: edition aborted." 2>&1
	git tag -d ${SNAPSHOT}
	exit 1
    fi

    mail -s "[OpenSMTPD] ${1} snapshot ${SNAPSHOT} available" misc@opensmtpd.org < ${TMP}
    if test $? != 0; then
	rm ${TMP}
	echo "Error: failed to send mail." >&2
	git tag -d ${SNAPSHOT}
	exit 1
    fi
    git push origin --tags ${SNAPSHOT}
    if test $? != 0; then
	echo "Error: failed to push tag." >&2
	git tag -d ${SNAPSHOT}
	exit 1
    fi
    rm ${TMP}
}


# called for `publish release`
#
release()
{
    echo not available yet
}

mkdir -p $FILES
$COMMAND $BRANCH
