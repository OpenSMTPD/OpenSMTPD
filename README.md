# OpenSMTPD

[![Version](https://img.shields.io/badge/Version-7.7.0p0-brihtgreen.svg)](https://github.com/OpenSMTPD/OpenSMTPD/releases/tag/7.7.0p0)
[![Coverity Scan analysis](https://scan.coverity.com/projects/278/badge.svg)](https://scan.coverity.com/projects/opensmtpd-opensmtpd)
[![Packaging status](https://repology.org/badge/tiny-repos/opensmtpd.svg)](https://repology.org/project/opensmtpd/versions)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](https://www.isc.org/licenses/)

> **Warning**
> This repository may be out of date compared to [OpenBSD smtpd source code](https://cvsweb.openbsd.org/src/usr.sbin/smtpd/). Downstream package maintainers should be aware of this when backporting security fixes and other changes.

OpenSMTPD is a FREE implementation of the server-side SMTP protocol as
defined by [RFC 5321](https://tools.ietf.org/html/rfc5321), with some
additional standard extensions.

It allows ordinary machines to exchange e-mails with other systems
speaking the SMTP protocol.

OpenSMTPD runs on various [Unix](https://en.wikipedia.org/wiki/Unix)
and Unix-like operating systems including:

- Linux
- [FreeBSD](https://www.freebsd.org)
- [OpenBSD](https://www.openbsd.org)
- [NetBSD](https://www.netbsd.org)
- [DragonFlyBSD](https://www.dragonflybsd.org)
- [macOS](https://en.wikipedia.org/wiki/MacOS)

For more information: http://www.opensmtpd.org/portable.html

If you are looking for a comprehensive manual on how to build your own mail server
visit our [wiki](https://github.com/OpenSMTPD/OpenSMTPD/wiki).

## Get in touch

If you want to stay up to day with most recent developments or chat about
OpenSMTPD you can:

- subscribe to our [mailing list](http://www.opensmtpd.org/list.html)
- join the IRC channel: `#opensmtpd` @ [irc.libera.chat](https://libera.chat)
- submit a bug report or a feature request here on [GitHub](https://github.com/OpenSMTPD/OpenSMTPD)
- visit GitHub's [discussions page](https://github.com/OpenSMTPD/OpenSMTPD/discussions)

## Documentation

The manual pages are available [online](https://www.opensmtpd.org/manual.html),
which you are encouraged to contribute to.

## Install via package manager

Many distributions already provide a packaged version of opensmtpd. All you need
to do is install it via your package manager.

> **Warning** Some distributions might ship old versions of OpenSMTPD, and some distributions may selectively backport security fixes and other code changes.

### Debian/Ubuntu

    sudo apt install opensmtpd

### Archlinux

Has a [dedicated wiki page](https://wiki.archlinux.org/index.php/OpenSMTPD#Installation)

### Alpine Linux

    apk install opensmtpd

### Fedora

    yum install opensmtpd

### macOS

OpenSMTPD is available from [MacPorts](https://www.macports.org):

    port install opensmtpd

## Install via container

Container images available at [this repo's packages page.](https://github.com/orgs/OpenSMTPD/packages)

## Install from source

### Install dependencies

OpenSMTPD relies on:

- [pkgconf](https://github.com/pkgconf/pkgconf) or [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/)
- [libevent](http://libevent.org/)
- [libressl](https://www.libressl.org/) or [OpenSSL](https://www.openssl.org/)

When not building from a release tarball (e.g. from the git
repository), the following dependencies are needed too:

- [autoconf](http://www.gnu.org/software/autoconf/)
- [automake](http://www.gnu.org/software/automake/)
- [bison](http://www.gnu.org/software/bison/) or [byacc](http://invisible-island.net/byacc/byacc.html)
- [libtool](http://www.gnu.org/software/libtool/)

By default OpenSMTPD expects latest versions of all dependencies unless noted
otherwise.

Note that some distributions have different packages for a same library, you
should always use the `-dev` or `-devel` package (for example, `libevent-dev`
or `libevent-devel`) if you're going to build OpenSMTPD yourself.

### Get the source code

Clone from github:

    git clone https://github.com/OpenSMTPD/OpenSMTPD.git

[Download tarball](https://github.com/OpenSMTPD/OpenSMTPD/archive/7.6.0p1.tar.gz)

Latest release can always be found [here](https://github.com/OpenSMTPD/OpenSMTPD/releases/latest)

### Compile

    cd opensmtpd*
    ./bootstrap  # Only if you build from git sources
    ./configure
    make
    sudo make install

#### Special notes for macOS

Please launch configure with special directive about libevent directory:

    ./configure --with-libevent=/opt/local

Though macOS includes a copy of bison in the bases system, you will
need to install a more recent version from, e.g., MacPorts.

### Install

    sudo make install

### Setup historical interface

OpenSMTPD provides a single utility `smtpctl` to control the daemon and
the local submission subsystem.

To accommodate systems that require historical interfaces such as `sendmail`,
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
links in their packages as it is very hard for us to accommodate all systems
with the preferred method in a clean way.

### Configure `/etc/smtpd.conf`

Please have a look at the complete format description of `smtpd.conf`
[configuration file](https://man.openbsd.org/smtpd.conf)

### Add OpenSMTPD users

To operate, OpenSMTPD requires at least one user, by default `_smtpd`; and
preferably two users, by default `_smtpd` and `_smtpq`.

Using two users instead of one will increase security by a large factor
so... if you want to voluntarily reduce security or you have absolute
more faith in our code than we do, by all means use one.

The instructions below assume the default users however, the configure
script allows overriding these using the options:
`--with-user-smtpd`, `--with-user-queue`, and `--with-group-queue`.

#### NetBSD, Linux (Debian, Arch Linux, ...)

    mkdir /var/empty
    useradd -c "SMTP Daemon" -d /var/empty -s /sbin/nologin _smtpd
    useradd -c "SMTPD Queue" -d /var/empty -s /sbin/nologin _smtpq

#### DragonFlyBSD, FreeBSD

    pw useradd _smtpd -c "SMTP Daemon" -d /var/empty -s /sbin/nologin
    pw useradd _smtpq -c "SMTPD Queue" -d /var/empty -s /sbin/nologin

#### macOS

First we need a group with an unused GID below `500`, list the current
ones used:

    /usr/bin/dscl . -list /Groups PrimaryGroupID | sort -n -k2,2

Add a group - here we have picked `444`:

    /usr/bin/sudo /usr/bin/dscl . -create /Groups/_smtpd PrimaryGroupID 444

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

### Launch smtpd

First, kill any running sendmail/exim/qmail/postfix or other.

Then:

    smtpd

or in debug and verbose mode

    smtpd -dv
