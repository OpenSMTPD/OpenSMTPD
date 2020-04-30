smtpscript
==========

smtpscript is a tool to write SMTP scenarios and easily implement regression tests for SMTP server-side implementations.

A smtpscript will look like:


    # this is a function init-helo that we want to call in all our regress tests
    proc init-helo {
        expect smtp ok
        writeln "HELO regress"
        expect smtp helo
    }
    
    # each of the test-case will be called sequentially
    test-case name "mailfrom.empty" {
        call init-helo
        writeln "MAIL FROM:<>"
        expect smtp ok
    }
    
    test-case name "mailfrom.broken" {
        call init-helo
        writeln "MAIL FROM:< @bleh>"
        expect smtp permfail
    }


which once executed, produces the output:

    $ smtpscript foo                                
    ===> running test-case "mailfrom.empty" ok
    ===> running test-case "mailfrom.broken" ok
    ===> all run
    passed: 2/2 (skipped: 0, failed: 0, error: 0)
    $


The scripting language also supports TLS, randomization and loops, so fairly complex scenarios can be achieved.
