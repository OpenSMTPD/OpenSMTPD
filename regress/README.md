# smtpd-regress

Regression test suite for OpenSMTPD.

Modeled on Alexander Bluhm's relayd-regress framework.  Each test forks a
controlled smtpd(8) process, an SMTP client, and an LMTP sink, then asserts
expected output in the daemon log.  No external test framework is required.

## Requirements

- OpenBSD with OpenSMTPD installed
- Perl 5 (base system)
- doas(1) or root access — smtpd(8) requires privilege
- makemap(8) — required for args-table-db.pl
- sqlite3(1) and opensmtpd-table-sqlite — required for args-table-sqlite.pl

## Running

```
make SUDO=doas
```

To test an alternative binary:

```
make SUDO=doas SMTPD=/path/to/smtpd
```

To enable kernel tracing:

```
make SUDO=doas KTRACE=ktrace
```

## Test cases

| File | What it tests |
|------|---------------|
| args-table-static.pl | Inline static table, K\_VIRTUAL lookup |
| args-table-file.pl | File backend, K\_VIRTUAL lookup |
| args-table-aliases.pl | File backend, K\_ALIAS lookup |
| args-table-db.pl | Berkeley DB backend via makemap(8) |
| args-table-sqlite.pl | SQLite backend via table-sqlite(8) |

## Writing a test

Each `args-*.pl` exports `%args` with keys `client`, `smtpd`, and `server`.

```perl
our %args = (
    client => {
        func    => \&smtp_client,
        to      => 'user@localhost',
        loggrep => qr/250 .* Message accepted for delivery/,
    },
    smtpd => {
        config  => [
            'table vusers { user@localhost = localuser }',
            'action "local" lmtp "$connectaddr:$connectport" virtual <vusers>',
            'match from local for local action "local"',
        ],
        loggrep => qr/stat=Delivered/,
    },
    server => {
        func    => \&lmtp_server,
        loggrep => qr/RCPT: RCPT TO:<localuser>/,
    },
);
```

The `smtpd` role accepts:

- `config` — smtpd.conf lines written before the listener directive; filter
  and table declarations must appear here
- `files` — filename to content map; files are written to the test working
  directory before smtpd starts
- `commands` — list of commands run after `files` are written (e.g. makemap)
- `filter_scripts` — scripts staged to a world-accessible tmpdir as `$filterdir`
- `listen_filter` — name of a declared filter to attach to the listener
- `loggrep` — regexp matched against smtpd.log; failure if no match

The following variables are substituted in `config` lines and `files` content:
`$listenaddr`, `$listenport`, `$connectaddr`, `$connectport`, `$objdir`,
`$filterdir`.

Pass `noserver => 1` in the `server` role to suppress the LMTP sink (e.g. for
rejection tests where no delivery is expected).

## Authors

Framework modeled on relayd-regress by Alexander Bluhm <bluhm@openbsd.org>.

Written by doom <doom@tagram.loom>.
