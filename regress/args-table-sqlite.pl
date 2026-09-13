# args-table-sqlite.pl -- SQLite-backed table for virtual address mapping
#
# Tests the table-sqlite(8) backend (stdio table protocol, converted 2024).
# Creates a SQLite database via sqlite3(1), writes a table-sqlite config file
# pointing at it, then verifies K_VIRTUAL lookup and LMTP delivery.
#
# Requires: opensmtpd-table-sqlite package, sqlite3(1).
# Set SQLITE3=/path/to/sqlite3 to override.

use strict;
use warnings;
use Cwd qw(getcwd);

my $sqlite3 = $ENV{SQLITE3} || "sqlite3";

our %args = (
    client => {
        func    => \&smtp_client,
        to      => 'sqltest@localhost',
        loggrep => qr/250 .* Message accepted for delivery/,
    },
    smtpd => {
        files => {
            # table-sqlite config: dbpath + query for virtual address lookup.
            # table-sqlite maps both K_ALIAS and K_VIRTUAL to query_alias;
            # query_virtual is not supported (see table-sqlite(5) examples).
            'sqlite-vusers.conf' =>
                "dbpath \$objdir/vusers.sqlite\n"
                . "query_alias SELECT destination FROM virtual"
                .  " WHERE source=?;\n",
        },
        commands => [
            [ $sqlite3, '$objdir/vusers.sqlite',
              "DROP TABLE IF EXISTS virtual;"
              . " CREATE TABLE virtual (source TEXT, destination TEXT);"
              . " INSERT INTO virtual VALUES"
              . " ('sqltest\@localhost', 'doom');" ],
        ],
        config => [
            'table vusers sqlite:$objdir/sqlite-vusers.conf',
            'action "local" lmtp "$connectaddr:$connectport" virtual <vusers>',
            'match from local for local action "local"',
        ],
        loggrep => qr/stat=Delivered/,
    },
    server => {
        func    => \&lmtp_server,
        loggrep => qr/RCPT: RCPT TO:<doom>/,
    },
);

1;
