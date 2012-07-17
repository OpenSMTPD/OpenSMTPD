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

Get the source
--------------

    git clone git://github.com/clongeau/opensmtpd.git

or

    visit http://www.opensmtpd.org/portable.html
    wget the latest snapshot
    tar xzvf opensmtpd-XXXXXXXXXXXX.tar.gz


Build
-----

    cd opensmtpd  
    ./bootstrap  
    ./configure  
    make  
    sudo make install  

### Special notes for FreeBSD/DragonFlyBSD:

Please launch configure with special directive about libevent directory:

#### FreeBSD:

    ./configure --with-libevent-dir=/usr/local

#### DragonFlyBSD:

    ./configure --with-libevent-dir=/usr/pkg


Create a /etc/mail/smtpd.conf
-----------------------------

    mkdir /etc/mail  
    cat > /etc/mail/smtpd.conf  
    listen on localhost  
    accept for all relay  
    ^D  
    

You can find a complete format description of [smtpd.conf configuration file](http://opensmtpd.org/smtpd.conf.5.html)


Add _smtpd user
---------------

### NetBSD, Linux (Debian, ArchLinux, ...)

    mkdir /var/empty  
    useradd -c "SMTP Daemon" -d /var/empty -s /sbin/nologin _smtpd

### DragonFlyBSD, FreeBSD

    pw useradd _smtpd -c "SMTP Daemon" -d /var/empty -s /sbin/nologin


Launch smtpd
------------

First, kill any running sendmail/exim/qmail/postfix or other.

Then:

    smtpd &

or in debug and verbose mode

    smtpd -dv


Manual pages
------------

    [smtpd](http://opensmtpd.org/smtpd.8.html) - Simple Mail Transfer Protocol daemon
    [smtpd.conf](http://opensmtpd.org/smtpd.conf.5.html) - Simple Mail Transfer Protocol daemon configuration file
    [smtpctl](http://opensmtpd.org/smtpctl.8.html) - control the Simple Mail Transfer Protocol daemon
    [newaliases](http://opensmtpd.org/newaliases.8.html) - generate aliases mappings for the Simple Mail Transfer Protocol daemon
    [makemap](http://opensmtpd.org/makemap.8.html) - generate mappings for the Simple Mail Transfer Protocol daemon
