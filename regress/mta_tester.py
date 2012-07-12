import socket
import threading
import random
try:
    import socketserver
except:
    import SocketServer as socketserver


class SMTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


class SMTPProtocol(object):

    def read_line(self):
        return self.cnx.read_line()

    def send_line(self, line):
        return self.cnx.send_line(line)

    def accept(self):
        self.send_line(random.choice( [ "200 Yeah, sure.",
                                        "200 Why not.",
                                        "200 Your call.",
                                        "200 I am here to serve, you know.",
                                        "200 My pleasure." ]))
    def permfail(self, msg = "No way", code = "500"):
        self.send_line('%s %s' % (code, msg))

    def tempfail(self, msg = "Maybe later", code = "400"):
        self.send_line('%s %s' % (code, msg))

    def read_data(self):
        r = []
        while 1:
            l = self.read_line()
            if l == '.':
                return r
            r.append(l)

    def _command(self, line):
        cmd = line.split()[0]
        func = getattr(self, 'on_%s' % cmd, None)
        if func is not None:
            func(*line.split()[1:])
        else:
            self.command(line)

    def command(self, line):
        self.permfail("Not implemented")

    def on_DATA(self, *args):
        self.accept()
        self.read_data()
        self.accept()


class SMTPSession(socketserver.StreamRequestHandler):

    def read_line(self):
        line = self.rfile.readline()
        if not line.endswith("\r\n"):
            raise ValueError
        return line[:-2]

    def send_line(self, line):
        print "<<< ", line
        self.wfile.write(line + "\r\n")


    def handle(self):
        self.proto = self.build_protocol()
        self.proto.cnx = self
        self.send_line("220 mtatest %s ESMTP" %
                       self.proto.__class__.__name__)
        while 1:
            line = self.read_line()
            print ">>> ", line
            if line == "QUIT":
                self.send_line("200 Ciao")
                break
            self.proto._command(line)

    def build_protocol(self):
        i = tests[0]
        tests[0] += 1
        cls = tests[1][i % len(tests[1])]
        print "TEST", cls
        return cls()


tests = [ 0, [] ]

def mtatest(cls):
    tests[1].append(cls)
    return cls

#@mtatest
class TestAcceptAll(SMTPProtocol):

    def command(self, line):
        self.accept()

@mtatest
class TestAdvertiseSTARTTLS_but_fail(TestAcceptAll):

    def on_EHLO(self, *args):
        self.send_line("200-STARTTLS")
        self.send_line("200 That's it")

    def on_STARTTLS(self, *args):
        self.permfail("April fool!")

if __name__ == "__main__":
    HOST, PORT = "localhost", 5657
    print tests
    server = SMTPServer((HOST, PORT), SMTPSession)
    server.serve_forever()
