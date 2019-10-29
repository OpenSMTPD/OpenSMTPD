# Release 6.6.0 #

## Dependencies note:

This release builds with LibreSSL > 3.0.2 or OpenSSL > 1.1.0.

It's preferable to depend on LibreSSL as OpenSMTPD is written and tested
with that dependency. In addition, the features parity is not respected,
some features will not be available with OpenSSL, like ECDSA server-side
certificates support in this release. OpenSSL library is considered as a
best effort target TLS library and provided as a commodity, LibreSSL has
become our target TLS library.


## Changes in this release (since 6.4.0):

- various improvements to documentation and code
- reverse dns session matching criteria added to smtpd.conf(5)
- regex table lookup support added to smtpd.conf(5)
- introduced support for ECDSA certificates with an ECDSA privsep engine
- introduced builtin filters for basic filtering of incoming sessions
- introduced option to deliver junk to a Junk folder in mail.maildir(8)
- fixed the smtp(1) client so it uses correct default port for SMTPS
- fixed an smtpd(8) crash on excessively large input
- ensured mail rejected by an LMTP server stay queued


## Experimental features:

- introduced a filters API to allow writing standalone filters for smtpd
- introduced proxy-v2 support allowing smtpd to operate behind a proxy
