#	$tagram.loom: Lmtp.pm,v 1.0 2026/04/13 doom Exp $

# Copyright (c) 2026 doom <doom@tagram.loom>
# Based on Server.pm by Alexander Bluhm <bluhm@openbsd.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use strict;
use warnings;

package Lmtp;
use parent 'Proc';
use Carp;
use Config;
use Socket qw(:DEFAULT IPPROTO_TCP TCP_NODELAY);
use Socket6;
use IO::Socket;
use IO::Socket::INET6;

# LMTP delivery sink.  Listens on a TCP port; smtpd connects and delivers
# messages via the LMTP protocol.  The actual LMTP conversation is driven
# by lmtp_server() in funcs.pl, keeping this class as a thin wrapper that
# only handles socket lifecycle — identical to Server.pm but with LMTP
# defaults and without SSL (smtpd delivers LMTP in cleartext locally).

sub new {
	my $class = shift;
	my %args = @_;
	$args{logfile} ||= "lmtp.log";
	$args{up} ||= "Accepted";
	my $self = Proc::new($class, %args);
	$self->{listendomain}
	    or croak "$class listen domain not given";
	my $ls = IO::Socket::INET6->new(
	    Proto		=> "tcp",
	    ReuseAddr		=> 1,
	    Domain		=> $self->{listendomain},
	    $self->{listenaddr} ? (LocalAddr => $self->{listenaddr}) : (),
	    $self->{listenport} ? (LocalPort => $self->{listenport}) : (),
	) or die ref($self), " IO::Socket::INET6 socket failed: $!";
	my $packstr = $Config{longsize} == 8 ? 'ql!' :
	    $Config{byteorder} == 1234 ? 'lxxxxl!xxxx' : 'xxxxll!';
	if ($self->{sndtimeo}) {
		setsockopt($ls, SOL_SOCKET, SO_SNDTIMEO,
		    pack($packstr, $self->{sndtimeo}, 0))
		    or die ref($self), " set SO_SNDTIMEO failed: $!";
	}
	if ($self->{rcvtimeo}) {
		setsockopt($ls, SOL_SOCKET, SO_RCVTIMEO,
		    pack($packstr, $self->{rcvtimeo}, 0))
		    or die ref($self), " set SO_RCVTIMEO failed: $!";
	}
	setsockopt($ls, IPPROTO_TCP, TCP_NODELAY, pack('i', 1))
	    or die ref($self), " set TCP_NODELAY failed: $!";
	listen($ls, 1)
	    or die ref($self), " socket listen failed: $!";
	my $log = $self->{log};
	print $log "listen sock: ", $ls->sockhost(), " ", $ls->sockport(), "\n";
	$self->{listenaddr} = $ls->sockhost() unless $self->{listenaddr};
	$self->{listenport} = $ls->sockport() unless $self->{listenport};
	$self->{ls} = $ls;
	return $self;
}

sub child {
	my $self = shift;

	shutdown(\*STDOUT, SHUT_WR);
	delete $self->{as};

	my $as = $self->{ls}->accept()
	    or die ref($self), " IO::Socket::INET6 socket accept failed: $!";
	print STDERR "accept sock: ", $as->sockhost(), " ", $as->sockport(), "\n";
	print STDERR "accept peer: ", $as->peerhost(), " ", $as->peerport(), "\n";

	*STDIN = *STDOUT = $self->{as} = $as;
}

1;
