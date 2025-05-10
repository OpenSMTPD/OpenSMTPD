# Release 7.7.0p0 (2025-05-12)

 - mail.lmtp: Correctly propagate LMTP permanent failures to smtpd.
 - Fixed connect filter request documentation in smtpd-filters.7.
 - Updated to new imsg APIs.

# Release 7.6.0p1 (2024-10-20)

 - fixed distribution tarball
 - added missing forward(5) documentation fix

# Release 7.6.0p0 (2024-10-13)

 - Introduced a new K_AUTH service to allow offloading the credentials
   to a proc table for non-crypt(3) authentication.  Helps with use
   cases like LDAP or custom auth.

 - Implement report responses for proc-filters too.

 - Changed the table protocol to a simpler text-based one.  Existing
   proc tables needs to be updated since old ones won't work.  The new
   protocol is documented in smtpd-tables(7).

 - Fixed the parsing of IPv6 addresses in file-backed table(5)

 - Document expected MDA behavior and the environment set by OpenSMTPD.

 - Set ORIGINAL_RECIPIENT in the environment of MDA scripts for
   compatibility with postfix.

 - Updated the bundled libtls.

# Release 7.5.0p0 (2024-04-10)

 - Added support for RFC 7505 "Null MX" handling and treat an MX of
   "localhost" as it were a "Null MX".

 - Allow inline tables and filter listings in smtpd.conf(5) to span
   over multiple lines.

 - Enabled DSN for the implicit socket too.

 - Added the `no-dsn' option for listen on socket too.

 - Reject headers that start with a space or a tab.

 - Fixed parsing of the ORCPT parameter.

 - Fixed table lookups of IPv6 addresses.

 - Fixed handling of escape characters in To, From and Cc headers.

 - Run LMTP deliveries as the recipient user again.

 - Disallow custom commands and file reading in root's .forward file.

 - Do not process other users .forward files when an alternate
   delivery user is provided in a dispatcher.

 - Unify the table(5) parser used in smtpd(8) and makemap(8).

 - Allow to use table(5) mappings on various match constraints.

Portability fixes:

 - re-add ASR_IPV4_BEFORE_IPV6 compile-time knob to prefer connecting
   to IPv6 instead of IPv4.

 - update asr(3) and imsg with OpenBSD.

 - fixed rpath handling on NetBSD in the configure.

# Release 7.4.0p1 (2023-11-16)

 - Fixed potential crash with LibreSSL versions prior 3.8 due to
   arc4random_buf() symbol clash.

 - Fixed manpage install path; reintroduced --with-mantype

 - Fixed typo in the configure help string: it's --without-libbsd

 - Fixed a couple of issues on MacOS:
   - Fixed typo that resulted in the re-declaration of strlcpy() and strlcat()
   - Cast suseconds_t to long for *printf
   - Fixed res_hnok() and b64_{pton,ntop}() discovery

# Release 7.4.0p0 (2023-10-25)

 - Avoid truncation of filtered data lines.
   Lines in the email body passed through a filter were truncated to
   roughly LINE_MAX bytes.

 - Allow arguments on NOOP.

 - Swap link-auth filter arguments and bump filter protocol version.
   It was ambiguous in the case the user name would contain a '|'
   character.

 - Add Message-ID as needed for messages received on the submission port.
   This was dropped during the incoming message parser refactor in 2018.

 - Drop ENGINE support.

 - Updated the bundled copy of libtls.
   This includes the removal of the support for TLS v1.0 and 1.1 as they
   were "MUST NOT use" for more than two years already.

The neverending cleanup of the -portable layer continued.  This
includes the complete rework of some parts:

 - Rework of the configure script:
   + use AC_SYSTEM_EXTENSIONS
   + better checks for libraries using AC_SEARCH_LIBS
   + dropped some useless and/or redundant checks
   + better checks for functions, shouldn't yield false-positives
   + various simplification to the -portable layer thanks to these
     changes

 - Simplified the `bootstrap` script.

# Release 7.3.0p2 (2023-09-20)

 - avoid potential use of uninitialized in ASN1_time_parse
 - backport ENGINE removal fix the build with newer LibreSSL

# Release 7.3.0p1 (2023-06-30)

 - add missing include of stdio.h for fparseln(3) on FreeBSD
 - fix a typo in the configure
 - use fatal() instead of err(3) in xclosefrom()
 - don't add "-lcrypto -lssl" thrice
 - fix the build of the bundled libtls with LibreSSL
 - force the use of the bundled libtls and libasr
 - append, not prepend, to LIBS during automatic configuration
 - do not add -L/usr/local/lib or -L/usr/lib, nor -I/usr/local/include
   or -I/usr/include as consequence of missing --with-libevent
 - optionally link libbsd-ctor too

# Release 7.3.0p0 (2023-06-17)

Includes the following security fixes:
  - OpenBSD 7.2 errata 20 "smtpd(8) could abort due to a
    connection from a local, scoped ipv6 address"
  - OpenBSD 7.2 errata 22 "Out of bounds accesses in libc resolver"

## Configuration changes
- The certificate to use is now selected by looking at the names found
  in the certificates themselves rather than the `pki` name.  The set
  of certificates for a TLS listener must be defined explicitly by
  using the `pki` listener option multiple times.

## Synced with OpenBSD 7.3
- OpenBSD 6.8:
  * Run LMTP deliveries as the smtpd user instead of the recipient
    user.
- OpenBSD 6.9:
  * Introduced smtp(1) `-a` to perform authentication before sending
    a message.
  * Fixed a memory leak in smtpd(8) resolver.
  * Prevented a crash due to premature release of resources by the
    smtpd(8) filter state machine.
  * Switch to libtls internally.
  * Change the way SNI works in smtpd.conf(5).  TLS listeners may be
    configured with multiple certificates.  The matching is based on
    the names included in the certificates.
  * Allow to specify TLS protocols and ciphers per listener and
    relay action.
- OpenBSD 7.0:
  * Fixed incorrect status code for expired mails resulting in
    misleading bounce report in smtpd(8).
  * Added TLS options `cafile=(path)`, `nosni`, `noverify` and
    `servername=(name)` to smtp(1).
  * Allowed specification of TLS ciphers and protocols in smtp(1).
- OpenBSD 7.1:
  * Stop verifying the cert or CA for a relay using opportunistic TLS.
  * Enabled TLS verify by default for outbound "smtps://" and
    "smtp+tls://", restoring documented smtpd(8) behavior.
- OpenBSD 7.3:
  * Prevented smtpd(8) abort due to a connection from a local,
    scoped ipv6 address.

## Portable layer changes
- libbsd and libtls are now optionally used if found.
  + Added `--with-libbsd`/`--without-libbsd` configure flag to enable
    linking to libbsd-overlay.
  + Added `--with-bundled-libtls` to force the usage of the bundled
    libtls.

    LibreTLS 3.7.0 (last version at the time of writing) and previous
    have a regression with OpenSSL 3+, so please use the bundled one.
    See the GitHub issue #1171 for more info.

- Updated and cleanup of the OpenBSD compats.
  + Ported `res_randomid()` from OpenBSD.

- The configure option `--with-path-CAfile` shouldn't be required
  anymore in most systems but it is retained since it could be useful in
  some configuration when using the bundled libtls.

- Various minor portability fixes.

# Release 6.8.0p2 (2020-12-24)

- Fixed an uninitialized variable and potential stack overflow with
  IPv6 connections in smtpd(8).
- Fixed smtpd(8) handling of user names containing "@" symbols.
- Allowed handling of long lines in an smtpd(8) aliases table.
- Removed mail.local(8) support for world-writable mail spools.

# Release 6.7.1p1 (2020-05-21)

- fixes a packaging issue causing asr.h to be installed in target
  system
- fixes a possible crash in the MTA when establishing IPv6 connections

# Release 6.7.0p1 (2020-05-21)

## New Features:

- Allowed use of the smtpd(8) session username in built-in filters
  when available.
- Introduced a `bypass` keyword to smtpd(8) so that built-in filters can
  bypass processing when a condition is met.
- Allowed use of 'auth' as an origin in smtpd.conf(5).
- Allowed use of mail-from and rctp-to as for and from parameters in
  smtpd.conf(5).

## Bug fixes:

- Ensured legacy ssl(8) session ID is persistent during a client TLS
  session, fixing an issue using TLSv1.3 with smtp.mail.yahoo.com.
- Fixed security vulnerabilities in smtpd(8). Corrected an
  out-of-bounds read in smtpd allowing an attacker to inject arbitrary
  commands into the envelope file to be executed as root, and ensured
  privilege revocation in smtpctl(8) to prevent arbitrary commands
  from being run with the _smtpq group.
- Allowed mail.local(8) to be run as non-root, opening a pipe to
  lockspool(1) for file locking.
- Fixed a security vulnerability in smtpd(8) which could lead to a
  privilege escalation on mbox deliveries and unprivileged code
  execution on lmtp deliveries.
- Added support for CIDR in a: spf atoms in smtpd(8).
- Fixed a possible crash in smtpd(8) when combining "from rdns" with
  nested virtual aliases under a particular configuration.

## Experimental Features:

- Introduced smtp-out event reporting.
- Improved filtering protocol.

# Release 6.6.4p1 (2020-02-24)

An out of bounds read in smtpd allows an attacker to inject arbitrary
commands into the envelope file which are then executed as
root. Separately, missing privilege revocation in smtpctl allows
arbitrary commands to be run with the _smtpq group.

# Release 6.6.3p1 (2020-02-10)

Following the 6.6.2p1 release, various improvements were done in OpenBSD -current to mitigate the risk of similar bugs.

This release back-ports them to the portable version of OpenSMTPD.

# Release 6.6.2p1 (2020-01-28)

This is CRITICAL security bugfix for
[CVE-2020-7247](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-7247)

Read more details in
[this blog post](https://poolp.org/posts/2020-01-30/opensmtpd-advisory-dissected/)

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
