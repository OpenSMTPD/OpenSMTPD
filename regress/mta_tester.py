import socket
import threading
import random
try:
    import socketserver
except:
    import SocketServer as socketserver


class SMTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


class SMTPSession(socketserver.StreamRequestHandler):

    def read_line(self):
        line = self.rfile.readline()
        if not line.endswith("\r\n"):
            raise ValueError
        return line[:-2]

    def send_line(self, line):
        self.wfile.write(line + "\r\n")

    def handle(self):
        self.send_line("220 your.worst.nightmare ESMTP")
        
        while 1:
            cmd = self.read_line()
            self.send_line(random.choice( [ "250 Yeah, sure.",
                                            "250 Why not.",
                                            "250 Your call.",
                                            "250 I am here to serve, you know.",
                                            "250 My pleasure." ]))
            if cmd == "DATA":
                while 1:
                    if self.read_line() == '.':
                        break
                self.send_line("250 Got it, dude.")
            if cmd == "QUIT":
                break


if __name__ == "__main__":
    HOST, PORT = "localhost", 5657
    server = SMTPServer((HOST, PORT), SMTPSession)
    server.serve_forever()
