# OpenSMTPD

[![Version](https://img.shields.io/badge/Version-6.6.1p1-brihtgreen.svg)](https://github.com/OpenSMTPD/OpenSMTPD/releases/tag/6.6.1p1)
[![Coverity Scan analysis](https://scan.coverity.com/projects/278/badge.svg)](https://scan.coverity.com/projects/opensmtpd-opensmtpd)
[![Packaging status](https://repology.org/badge/tiny-repos/opensmtpd.svg)](https://repology.org/project/opensmtpd/versions)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://www.isc.org/licenses/)
[![Clang Analysis](https://opensmtpd.email/reports/clang/badge.svg)](https://opensmtpd.email/reports/clang/index.html)


OpenSMTPD is a FREE implementation of the server-side SMTP protocol as
defined by [RFC 5321](https://tools.ietf.org/html/rfc5321), with some
additional standard extensions.

It allows ordinary machines to exchange e-mails with other systems
speaking the SMTP protocol.

OpenSMTPD runs on top of the OpenBSD operating system but also has a
portable version that can build and run on several systems, including:

* Linux
* FreeBSD
* NetBSD
* DragonFly

For more information: http://www.opensmtpd.org/portable.html

People interested about OpenSMTPD are encouraged to subscribe to our
mailing list: http://www.opensmtpd.org/list.html

and to join the IRC channel: #OpenSMTPD @ irc.freenode.net

Also note that we have a wiki at
https://github.com/OpenSMTPD/OpenSMTPD/wiki that you are encouraged to
contribute to.

Cheers!


# How to build, configure and use Portable OpenSMTPD

## Dependencies

Portable OpenSMTPD relies on:
  * autoconf (http://www.gnu.org/software/autoconf/)
  * automake (http://www.gnu.org/software/automake/)
  * bison (http://www.gnu.org/software/bison/)
    or byacc (http://invisible-island.net/byacc/byacc.html)
  * libevent (http://libevent.org/)
  * libtool (http://www.gnu.org/software/libtool/)
  * libressl (https://www.libressl.org/)
    or OpenSSL (https://www.openssl.org/)


By default OpenSMTPD expects latest versions of all dependencies unless noted otherwise.

Note that some distributions have different packages for a same library, you should always use the `-dev` or `-devel` package (for example, `libevent-dev` or `libevent-devel`) if you're going to build OpenSMTPD yourself.


## Get the source

    git clone -b portable git://github.com/OpenSMTPD/OpenSMTPD.git opensmtpd


## Build

    cd opensmtpd*
    ./bootstrap  # Only if you build from git sources
    ./configure
    make
    sudo make install

### Special notes for FreeBSD/DragonFlyBSD/Mac OS X:

Please launch configure with special directive about libevent and
libasr directory:

### FreeBSD / DragonFlyBSD:

    ./configure --with-libasr=/usr/local

### Mac OS X:

    ./configure --with-libevent=/opt/local --with-libasr=/opt/local


## Install

    sudo make install


## Setup historical interface

OpenSMTPD provides a single utility `smtpctl` to control the daemon and
the local submission subsystem.

To accomodate systems that require historical interfaces such as `sendmail`,
`newaliases` or `makemap`, the `smtpctl` utility can operate in compatibility
mode if called with the historical name.

On mailwrapper-enabled systems, this is achieved by editing `/etc/mailer.conf`
and adding the following lines:

    sendmail        /usr/sbin/smtpctl
    send-mail       /usr/sbin/smtpctl
    mailq           /usr/sbin/smtpctl
    makemap         /usr/sbin/smtpctl
    newaliases      /usr/sbin/smtpctl


Whereas on systems that don't provide mailwrapper, it can be achieved by
setting the appropriate symbolic links:

    ln -s /usr/sbin/smtpctl sendmail
    ln -s /usr/sbin/smtpctl send-mail
    ln -s /usr/sbin/smtpctl mailq
    ln -s /usr/sbin/smtpctl makemap
    ln -s /usr/sbin/smtpctl newaliases


The OpenSMTPD project leaves it up to the package maintainers to setup the
links in their packages as it is very hard for us to accomodate all systems
with the prefered method in a clean way.


## Configure /etc/smtpd.conf

Please have a look at the complete format description of smtpd.conf
configuration file (https://man.openbsd.org/smtpd.conf)


## Add OpenSMTPD users

To operate, OpenSMTPD requires at least one user, by default `_smtpd`; and
preferably two users, by default `_smtpd` and `_smtpq`.

Using two users instead of one will increase security by a large factor
so... if you want to voluntarily reduce security or you have absolute
more faith in our code than we do, by all means use one.


The instructions below assume the default users however, the configure
script allows overriding these using the options:
`--with-user-smtpd`, `--with-user-queue`, and `--with-group-queue`.


### NetBSD, Linux (Debian, Arch Linux, ...)

    mkdir /var/empty  
    useradd -c "SMTP Daemon" -d /var/empty -s /sbin/nologin _smtpd
    useradd -c "SMTPD Queue" -d /var/empty -s /sbin/nologin _smtpq

### DragonFlyBSD, FreeBSD

    pw useradd _smtpd -c "SMTP Daemon" -d /var/empty -s /sbin/nologin
    pw useradd _smtpq -c "SMTPD Queue" -d /var/empty -s /sbin/nologin

### Mac OS X

First we need a group with an unused GID below `500`, list the current
ones used:

	/usr/bin/dscl . -list /Groups PrimaryGroupID | sort -n -k2,2

Add a group - here we have picked `444`:

	/usr/bin/sudo /usr/bin/dscl . -create /Groups/_smtpd
	PrimaryGroupID 444

Then the user. Again we need an unused UID below `500`, list the current
ones used:

	/usr/bin/dscl . -list /Users UniqueID | sort -n -k2,2

Add a user - here we have picked `444`:

	/usr/bin/sudo /usr/bin/dscl . -create /Users/_smtpd UniqueID 444
	/usr/bin/sudo /usr/bin/dscl . -delete /Users/_smtpd AuthenticationAuthority
	/usr/bin/sudo /usr/bin/dscl . -delete /Users/_smtpd PasswordPolicyOptions
	/usr/bin/sudo /usr/bin/dscl . -delete /Users/_smtpd dsAttrTypeNative:KerberosKeys
	/usr/bin/sudo /usr/bin/dscl . -delete /Users/_smtpd dsAttrTypeNative:ShadowHashData
	/usr/bin/sudo /usr/bin/dscl . -create /Users/_smtpd RealName "SMTP Daemon"
	/usr/bin/sudo /usr/bin/dscl . -create /Users/_smtpd Password "*"
	/usr/bin/sudo /usr/bin/dscl . -create /Users/_smtpd PrimaryGroupID 444
	/usr/bin/sudo /usr/bin/dscl . -create /Users/_smtpd NFSHomeDirectory /var/empty
	/usr/bin/sudo /usr/bin/dscl . -create /Users/_smtpd UserShell /usr/bin/false

repeat for the `_smtpq` user.


## Launch smtpd

First, kill any running sendmail/exim/qmail/postfix or other.

Then:

    smtpd

or in debug and verbose mode

    smtpd -dv

