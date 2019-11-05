# Release 6.6.1p1 (2019-11-06)

## Changes in this release (since 6.6.0p1)

This is a bugfix release. No new features were added.

- Fixed crash on recipient expansion [#968](https://github.com/OpenSMTPD/OpenSMTPD/issues/968)
- Fixed broken build with LibreSSL [#944](https://github.com/OpenSMTPD/OpenSMTPD/issues/944)
- Fixed crash in `arc4random` caused by differences in OpenSSL vs LibreSSL compatibility layer plumbing [#958](https://github.com/OpenSMTPD/OpenSMTPD/issues/958)  
- Fixed issue where `from any` rules never matched by IPv6 sources [#969](https://github.com/OpenSMTPD/OpenSMTPD/issues/969)
- Fixed crash that happened during mail relay on musl distros [#929](https://github.com/OpenSMTPD/OpenSMTPD/issues/929)
- Added reference aliases file in `etc/aliases`
- Fixed multiple compilation warnings 
[#965](https://github.com/OpenSMTPD/OpenSMTPD/issues/965)
[#966](https://github.com/OpenSMTPD/OpenSMTPD/issues/966)
[#967](https://github.com/OpenSMTPD/OpenSMTPD/issues/967)
[#978](https://github.com/OpenSMTPD/OpenSMTPD/issues/978)
[#977](https://github.com/OpenSMTPD/OpenSMTPD/issues/977)
[#975](https://github.com/OpenSMTPD/OpenSMTPD/issues/975)



# Release 6.6.0p1 (2019-10-26)

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
