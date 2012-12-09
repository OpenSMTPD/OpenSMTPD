Preliminary note
================

[smtpd](http://www.openbsd.org/cgi-bin/cvsweb/src/usr.sbin/smtpd/) also known as
OpenSMTPD is a [smtp server implementation for OpenBSD](http://http://opensmtpd.org/smtpd.8.html).
It is still a work in progress which still lacks many features.

Then, on top of that, all OpenSMTPD's features are not ported yet. For instance,
authentification still doesn't work.

People interested about portable OpenSMTPD, or about OpenSMTPD in general, are
encouraged to join the IRC channel #opensmtpd @ FreeNode.net.


How to use Portable OpenSMTPD
=============================

Dependencies
------------

OpenSMTPD relies on:
* [autoconf](http://www.gnu.org/software/autoconf/)
* [automake](http://www.gnu.org/software/automake/)
* [Berkeley DB](http://www.oracle.com/technetwork/products/berkeleydb/overview/index.html)
* [bison](http://www.gnu.org/software/bison/) (or [byacc](http://invisible-island.net/byacc/byacc.html))
* [libevent](http://libevent.org/)
* [libtool](http://www.gnu.org/software/libtool/)
* [openssl](http://www.openssl.org/)
* [sqlite3](http://sqlite.org/)
* [zlib](http://www.zlib.net/)


Get the source
--------------

    git clone -b portable git://github.com/poolpOrg/OpenSMTPD.git opensmtpd

or

    wget http://www.opensmtpd.org/archives/opensmtpd-portable-latest.tar.gz
    tar xzvf opensmtpd-portable-latest.tar.gz


Build
-----

    cd opensmtpd*
    ./bootstrap  
    ./configure  
    make  
    sudo make install  

### Special notes for FreeBSD/DragonFlyBSD/Mac OS X:

Please launch configure with special directive about libevent directory:

#### FreeBSD:

    ./configure --with-libevent-dir=/usr/local

#### DragonFlyBSD:

    ./configure --with-libevent-dir=/usr/pkg

#### Mac OS X:

    ./configure --with-libevent-dir=/opt/local
    make CFLAGS="-DBIND_8_COMPAT=1"


Install
-------

    sudo make install    


Configure /etc/smtpd.conf
-------------------------

Please have a look at the complete format description of [smtpd.conf configuration file](http://opensmtpd.org/smtpd.conf.5.html)

Add _smtpd user
---------------

### NetBSD, Linux (Debian, ArchLinux, ...)

    mkdir /var/empty  
    useradd -c "SMTP Daemon" -d /var/empty -s /sbin/nologin _smtpd

### DragonFlyBSD, FreeBSD

    pw useradd _smtpd -c "SMTP Daemon" -d /var/empty -s /sbin/nologin

### Mac OS X

First we need a group with an unused GID below 500, list the current ones used:

	/usr/bin/dscl . -list /Groups PrimaryGroupID | sort -n -k2,2

Add a group - here we have picked 444:

	/usr/bin/sudo /usr/bin/dscl . -create /Groups/_smtpd PrimaryGroupID 444

Then the user. Again we need an unused UID below 500, list the current ones used:

	/usr/bin/dscl . -list /Users UniqueID | sort -n -k2,2

Add a user - here we have picked 444:

	/usr/bin/sudo /usr/bin/dscl . -create /Users/_smtpd UniqueID 444
	/usr/bin/sudo /usr/bin/dscl . -delete /Users/_smtpd AuthenticationAuthority
	/usr/bin/sudo /usr/bin/dscl . -delete /Users/_smtpd PasswordPolicyOptions
	/usr/bin/sudo /usr/bin/dscl . -delete /Users/_smtpd dsAttrTypeNative:KerberosKeys
	/usr/bin/sudo /usr/bin/dscl . -delete /Users/_smtpd dsAttrTypeNative:ShadowHashData
	/usr/bin/sudo /usr/bin/dscl . -create /Users/_smtpd RealName "SMTP Daemon"
	/usr/bin/sudo /usr/bin/dscl . -create /Users/_stmpd Password "*"
	/usr/bin/sudo /usr/bin/dscl . -create /Users/_smtpd PrimaryGroupID 444
	/usr/bin/sudo /usr/bin/dscl . -create /Users/_smtpd NFSHomeDirectory \
		/var/empty
	/usr/bin/sudo /usr/bin/dscl . -create /Users/_smtpd UserShell /usr/bin/false


Launch smtpd
------------

First, kill any running sendmail/exim/qmail/postfix or other.

Then:

    smtpd &

or in debug and verbose mode

    smtpd -dv


Manual pages
------------

* [aliases](http://opensmtpd.org/aliases.5.html) - 
* [forward](http://opensmtpd.org/forward.5.html) - 
* [smtpd](http://opensmtpd.org/smtpd.8.html) - Simple Mail Transfer Protocol daemon
* [smtpd.conf](http://opensmtpd.org/smtpd.conf.5.html) - Simple Mail Transfer Protocol daemon configuration file
* [smtpctl](http://opensmtpd.org/smtpctl.8.html) - control the Simple Mail Transfer Protocol daemon
* [newaliases](http://opensmtpd.org/newaliases.8.html) - generate aliases mappings for the Simple Mail Transfer Protocol daemon
* [makemap](http://opensmtpd.org/makemap.8.html) - generate mappings for the Simple Mail Transfer Protocol daemon
