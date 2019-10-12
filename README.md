# Preliminary note

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
  * libasr (https://opensmtpd.org/archives/libasr-1.0.2.tar.gz)


## Get the source

    git clone -b portable git://github.com/OpenSMTPD/OpenSMTPD.git opensmtpd


## Build

    cd opensmtpd*
    ./bootstrap  # Only if you build from git sources
    ./configure
    make
    sudo make install


## Special notes for FreeBSD/DragonFlyBSD/Mac OS X:

Please launch configure with special directive about libevent and
libasr directory:

### FreeBSD / DragonFlyBSD:

    ./configure --with-libasr=/usr/local

### Mac OS X:

    ./configure --with-libevent=/opt/local --with-libasr=/opt/local


## Install

    sudo make install


### Setup historical interface

OpenSMTPD provides a single utility `smtpctl` to control the daemon and
the local submission subsystem.

To accomodate systems that require historical interfaces such as `sendmail`,
`newaliases` or `makemap`, the `smtpctl` utility can operate in compatibility
mode if called with the historical name.

On mailwrapper-enabled systems, this is achieved by editing /etc/mailer.conf
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


### Configure /etc/smtpd.conf

Please have a look at the complete format description of smtpd.conf
configuration file (https://man.openbsd.org/smtpd.conf)


### Add OpenSMTPD users

To operate, OpenSMTPD requires at least one user, by default `_smtpd`; and
preferably two users, by default `_smtpd` and `_smtpq`.

Using two users instead of one will increase security by a large factor
so... if you want to voluntarily reduce security or you have absolute
more faith in our code than we do, by all means use one.


The instructions below assume the default users however, the configure
script allows overriding these using the options:
--with-user-smtpd, --with-user-queue, and --with-group-queue.


### NetBSD, Linux (Debian, Arch Linux, ...)

    mkdir /var/empty  
    useradd -c "SMTP Daemon" -d /var/empty -s /sbin/nologin _smtpd
    useradd -c "SMTPD Queue" -d /var/empty -s /sbin/nologin _smtpq

### DragonFlyBSD, FreeBSD

    pw useradd _smtpd -c "SMTP Daemon" -d /var/empty -s /sbin/nologin
    pw useradd _smtpq -c "SMTPD Queue" -d /var/empty -s /sbin/nologin

### Mac OS X

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


## Docker version

OpenSMTPD provides a convenient docker file for getting started quickly with
development or usage.

### Short reference

Default OpenSMTPD config only accepts localhost connections, so mount your own config if you want to talk to smtpd from outside.

Exposed ports: 
* 25
* 465 
* 587

Volumes: 
* `/etc/mail` - configuration directory
* `/var/spool/smtpd` - state directory of smtpd

See [Dockerfile](Dockerfile) for details


### Build

First, you need to build the container:

    docker build -t opensmtpd-dev .

This will build the container with OpenSMTPD and run some tests. If everything
went ok you can run the container.

### Run 

To run the container execute the following command:

> port 10025 was chosen to avoid possible permission denied errors. 
> Any port above 1024 should work):

    docker run --rm -ti -p 10025:25 opensmtpd-dev


Container's port 25 will be exposed on your localhost port 10025. However
OpenSMTPD's default config only accepts local (relevant to smtpd) connections,
so if you attempt to talk to port 10025 you will see:

    [~]$ telnet localhost 10025
    Trying ::1...
    Connected to localhost.
    Escape character is '^]'.
    Connection closed by foreign host.

Luckily there is a way to change this. You will need to mount your own
directory with configuration files. Create a folder somewhere and put your
`smtpd.conf` there. In this example the folder on local machine that contains
custom config is [docker/examples/config](docker/examples/config) and it allows delivery for local recipients
from any source

    docker run --rm -ti -p 10025:25 -v $(pwd)/docker/examples/config:/etc/mail opensmtpd-dev:latest 


So now you can try sending [test email](tests/test_email_noauth.txt) like this:

    awk '{print $0; system("sleep .1");}' "tests/test_email_noauth.txt"  | nc localhost 10025

    220 60f5076d05ff ESMTP OpenSMTPD
    250 60f5076d05ff Hello localhost [172.17.0.1], pleased to meet you
    250 2.0.0 Ok
    250 2.1.5 Destination address valid: Recipient ok
    354 Enter mail, end with "." on a line by itself
    250 2.0.0 2da6a23e Message accepted for delivery
    221 2.0.0 Bye

In the same way you can mount a directory to persist OpenSMTPD's data. Just mount
a directory to /var/spool/smtpd

    docker run --rm -ti -p 10025:25 \
    -v $(pwd)/docker/examples/config:/etc/mail \
    -v ~/tmp/mail:/var/spool/smtpd \
    opensmtpd-dev:latest

> Since OpenSMTPD requires data volume to be owned by root and have strictly set
> permissions the directory that you mount to `/var/spool/smtpd` will get chown'ed
> to root with 711 permissions. (At this moment I don't know a good way to fix this)

