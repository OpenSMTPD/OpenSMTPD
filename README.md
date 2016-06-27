Preliminary note
================

OpenSMTPD is a FREE implementation of the server-side SMTP protocol as
defined by RFC 5321, with some additional standard extensions.

It allows ordinary machines to exchange e-mails with other systems
speaking the SMTP protocol.

OpenSMTPD runs on top of the OpenBSD operating system but also has a
portable version that can build and run on several systems, including:

* Linux
* FreeBSD
* NetBSD
* DragonFly
* MacOSX

For more information: http://www.opensmtpd.org/portable.html

People interested about OpenSMTPD are encouraged to subscribe to our
mailing list: http://www.opensmtpd.org/list.html

and to join the IRC channel: #OpenSMTPD @ irc.freenode.net

Also note that we have a wiki at
https://github.com/OpenSMTPD/OpenSMTPD/wiki that you are encouraged to
contribute to.

Cheers!


How to build, configure and use Portable OpenSMTPD
==================================================

Dependencies
------------

Portable OpenSMTPD relies on:
  * autoconf (http://www.gnu.org/software/autoconf/)
  * automake (http://www.gnu.org/software/automake/)
  * bison (http://www.gnu.org/software/bison/)
    or byacc (http://invisible-island.net/byacc/byacc.html)
  * libevent (http://libevent.org/)
  * libtool (http://www.gnu.org/software/libtool/)
  * openssl (http://www.openssl.org/)
  * libasr (https://opensmtpd.org/archives/libasr-1.0.2.tar.gz)


Get the source
--------------

    git clone -b portable git://github.com/OpenSMTPD/OpenSMTPD.git opensmtpd

or

    wget http://www.opensmtpd.org/archives/opensmtpd-portable-latest.tar.gz
    tar xzvf opensmtpd-portable-latest.tar.gz


Build
-----

    cd opensmtpd*
    ./bootstrap  # Only if you build from git sources
    ./configure
    make
    sudo make install

# Special notes for FreeBSD/DragonFlyBSD/Mac OS X:

Please launch configure with special directive about libevent and
libasr directory:

# FreeBSD / DragonFlyBSD:

    ./configure --with-asr=/usr/local

# Mac OS X:

    ./configure --with-libevent-dir=/opt/local --with-asr=/opt/local


Install
-------

    sudo make install


Configure /etc/smtpd.conf
-------------------------

Please have a look at the complete format description of smtpd.conf
configuration file (http://opensmtpd.org/smtpd.conf.5.html)


Add OpenSMTPD users
-------------------

To operate, OpenSMTPD requires at least one user, by default _smtpd; and
preferably two users, by default _smtpd and _smtpq.

Using two users instead of one will increase security by a large factor
so... unless you want to voluntarily reduce security or you have
absolute more faith in our code than we do, by all means use one.


The instructions below assume the default users however, the configure
script allows overriding these using the options:
--with-privsep-user, --with-queue-user.


# NetBSD, Linux (Debian, Arch Linux, ...)

    mkdir /var/empty  
    useradd -c "SMTP Daemon" -d /var/empty -s /sbin/nologin _smtpd
    useradd -c "SMTPD Queue" -d /var/empty -s /sbin/nologin _smtpq

# DragonFlyBSD, FreeBSD

    pw useradd _smtpd -c "SMTP Daemon" -d /var/empty -s /sbin/nologin
    pw useradd _smtpq -c "SMTPD Queue" -d /var/empty -s /sbin/nologin

# Mac OS X

First we need a group with an unused GID below 500, list the current
ones used:

	/usr/bin/dscl . -list /Groups PrimaryGroupID | sort -n -k2,2

Add a group - here we have picked 444:

	/usr/bin/sudo /usr/bin/dscl . -create /Groups/_smtpd
	PrimaryGroupID 444

Then the user. Again we need an unused UID below 500, list the current
ones used:

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
	/usr/bin/sudo /usr/bin/dscl . -create /Users/_smtpd NFSHomeDirectory /var/empty
	/usr/bin/sudo /usr/bin/dscl . -create /Users/_smtpd UserShell /usr/bin/false

repeat for the _smtpq user.


Launch smtpd
------------

First, kill any running sendmail/exim/qmail/postfix or other.

Then:

    smtpd

or in debug and verbose mode

    smtpd -dv
