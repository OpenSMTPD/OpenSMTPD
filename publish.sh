#! /bin/sh
#

DEBUG=0
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


# builds a tarball from current branch and returns its name
#
build_tarball()
{
    V=5.3
    P=p1
    ASRSRC=/usr/src/lib/libc/asr
    ASRFILES="asr.c asr_debug.c asr_utils.c gethostnamadr_async.c
	      res_send_async.c getaddrinfo_async.c getnameinfo_async.c
	      res_search_async.c asr.h asr_private.h"

    T=`mktemp -d /tmp/publish.XXXXXXXXXX` || {
	echo "error: failed to mktemp" >&2
	exit 1
    }
    CURDIR=`pwd`
    if echo "$1" | grep -vE '(portable|p[0-9])$' >/dev/null; then
	TARGET=opensmtpd-${V}
	git archive --format=tar --prefix=${TARGET}/ ${1}:smtpd/ | \
	    (cd ${T} && tar xf -)
	for i in ${ASRFILES}; do cp ${ASRSRC}/$i ${T}/${TARGET}/; done
	cat ${T}/${TARGET}/smtpd/Makefile |	\
	    sed 's/-I\/usr\/src\/lib\/libc\/asr//' |	\
	    sed 's/\/usr\/src\/lib\/libc\/asr//' > ${T}/_makefile
	cat ${T}/_makefile > ${T}/${TARGET}/smtpd/Makefile
    else
	TARGET=opensmtpd-${V}${P}
	git archive --format=tar --prefix=${TARGET}/ ${1} | \
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
    REMOTEHOST=ssh.poolp.org
    REMOTEDIR=/var/www/virtual/org.opensmtpd/archives/

    TARBALL=`build_tarball ${1}`
    SNAPSHOT=opensmtpd-`date +%Y%m%d%H%M`
    if test "${1}" = "portable"; then
	SNAPSHOT=${SNAPSHOT}p1
    fi
    git tag ${SNAPSHOT}
    mv ${FILES}/${TARBALL} ${FILES}/${SNAPSHOT}.tar.gz

    if test "${1}" = "master"; then
	LASTTAGS=`git tag |grep '^opensmtpd-[0-9][0-9][0-9]*' | grep -v '[0-9]p[0-9]$' | tail -2 | tr '\n' '@' | sed 's/@$//g'| sed 's/@/../g'`
    else
	LASTTAGS=`git tag |grep '^opensmtpd-[0-9][0-9][0-9]*' | grep '[0-9]p[0-9]$' | tail -2 | tr '\n' '@' | sed 's/@$//g'| sed 's/@/../g'`
    fi

    echo git log $LASTTAGS

    CHANGELOG=`git log $LASTTAGS`
    if test "${CHANGELOG}" = ""; then
	echo "Error: nothing new in this snapshot, I won't publish it !" >&2
	git tag -d ${SNAPSHOT}
	exit 1
    fi

    
    scp -pr ${FILES}/${SNAPSHOT}.tar.gz ${REMOTEHOST}:${REMOTEDIR}
    if test $? != 0; then
	echo "Error: could not publish snapshot !" >&2
	git tag -d ${SNAPSHOT}
	exit 1
    fi

    if test "${1}" = "master"; then
	ssh ${REMOTEHOST} "cd ${REMOTEDIR}; rm -f opensmtpd-latest.tar.gz; ln -s ${SNAPSHOT}.tar.gz opensmtpd-latest.tar.gz"
    else
	ssh ${REMOTEHOST} "cd ${REMOTEDIR}; rm -f opensmtpd-portable-latest.tar.gz; ln -s ${SNAPSHOT}.tar.gz opensmtpd-portable-latest.tar.gz"
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

    if test "${DEBUG}" = "1"; then
	mail -s "[OpenSMTPD] ${1} snapshot ${SNAPSHOT} available" `whoami` < ${TMP}
    else
	ssh ${REMOTEHOST} "mail -s '[OpenSMTPD] ${1} snapshot ${SNAPSHOT} available' misc@opensmtpd.org" < ${TMP}
    fi

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
    REMOTEHOST=ssh.poolp.org
    REMOTEDIR=/var/www/virtual/org.opensmtpd/archives/
    X=5
    Y=1
    Z=0

    TARBALL=`build_tarball ${1}`
    if test "$Z" = "0"; then
	RELEASE=opensmtpd-$X.$Y
    else
	RELEASE=opensmtpd-$X.$Y.$Z
    fi

    if test "${1}" = "portable"; then
	RELEASE=${RELEASE}p1
    fi
    git tag ${RELEASE}
    mv ${FILES}/${TARBALL} ${FILES}/${RELEASE}.tar.gz

    if test "${1}" = "master"; then
	LASTTAGS=`git tag |grep '^opensmtpd-[0-9].[0-9]*' | grep -v '[0-9]p[0-9]$' | tail -2 | tr '\n' '@' | sed 's/@$//g'| sed 's/@/../g'`
    else
	LASTTAGS=`git tag |grep '^opensmtpd-[0-9].[0-9]*' | grep '[0-9]p[0-9]$' | tail -2 | tr '\n' '@' | sed 's/@$//g'| sed 's/@/../g'`
    fi

    CHANGELOG=`git log $LASTTAGS`
    if test "${CHANGELOG}" = ""; then
	echo "Error: nothing new in this release, I won't publish it !" >&2
	git tag -d ${RELEASE}
	exit 1
    fi

    
    scp -pr ${FILES}/${RELEASE}.tar.gz ${REMOTEHOST}:${REMOTEDIR}
    if test $? != 0; then
	echo "Error: could not publish release !" >&2
	git tag -d ${RELEASE}
	exit 1
    fi

    TMP=`mktemp /tmp/publish.XXXXXXXX` || {
	echo "error: mktemp failed" >&2
	git tag -d ${RELEASE}
	exit 1
    }

    cat <<EOF > ${TMP}
User `whoami` has just rebuilt a ${1} release,
available from:

        http://www.OpenSMTPD.org/archives/${RELEASE}.tar.gz

XXX

Summary of changes since last snapshot:
---------------------------------------
${CHANGELOG}
EOF
    ${EDITOR} ${TMP}

    if test $? != 0; then
	rm ${TMP}
	echo "Error: edition aborted." 2>&1
	git tag -d ${RELEASE}
	exit 1
    fi

    if test "${DEBUG}" = "1"; then
	mail -s "[OpenSMTPD] ${1} release ${RELEASE} available" `whoami` < ${TMP}
    else
	ssh ${REMOTEHOST} "mail -s '[OpenSMTPD] ${1} release ${RELEASE} available' misc@opensmtpd.org" < ${TMP}
    fi

    if test $? != 0; then
	rm ${TMP}
	echo "Error: failed to send mail." >&2
	git tag -d ${RELEASE}
	exit 1
    fi
    git push origin --tags ${RELEASE}
    if test $? != 0; then
	echo "Error: failed to push tag." >&2
	git tag -d ${RELEASE}
	exit 1
    fi
    rm ${TMP}
}

mkdir -p $FILES
$COMMAND $BRANCH
