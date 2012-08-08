import copy
import random
import socket
import sys
import thread
import time


class SMTPConnection():
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

    def disconnect(self):
        self.socket.close()

    def read_line(self):
        return self.socket.recv(1024)

    def send_line_crlf(self, line):
        self.socket.send(line + "\r\n")

    def send_line_cr(self, line):
        self.socket.send(line + "\r")

    def send_line_lf(self, line):
        self.socket.send(line + "\n")



class SMTPTester():
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def sane(self, mail_from, rcpt_to):
        s = SMTPConnection(self.host, self.port)
        s.connect()
        s.read_line()

        s.send_line_crlf("HELO smtp_tester.py");
        s.read_line()
    
        s.send_line_crlf("MAIL FROM: <" + mail_from + ">");
        s.read_line()

        s.send_line_crlf("RCPT TO: <" + rcpt_to + ">");
        s.read_line()

        s.send_line_crlf("DATA");
        s.read_line()

        for i in range(0, 20):
            s.send_line_crlf("a");
        s.send_line_crlf(".");
        s.read_line()

        s.send_line_crlf("QUIT");
        s.read_line()

        s.disconnect()

    def connect_disconnect(self, mail_from, rcpt_to):
        s = SMTPConnection(self.host, self.port)
        s.connect()
        s.disconnect()

    def disconnect_after_banner(self, mail_from, rcpt_to):
        s = SMTPConnection(self.host, self.port)
        s.connect()
        s.read_line()
        s.disconnect()

    def disconnect_after_helo(self, mail_from, rcpt_to):
        s = SMTPConnection(self.host, self.port)
        s.connect()
        s.read_line()
        s.send_line_crlf("HELO smtp_tester.py");
        s.disconnect()

    def disconnect_after_mail_from(self, mail_from, rcpt_to):
        s = SMTPConnection(self.host, self.port)
        s.connect()
        s.read_line()
        s.send_line_crlf("HELO smtp_tester.py");
        s.read_line()
        s.send_line_crlf("MAIL FROM: <"+ mail_from +">");
        s.disconnect()

    def disconnect_after_rcpt_to(self, mail_from, rcpt_to):
        s = SMTPConnection(self.host, self.port)
        s.connect()
        s.read_line()
        s.send_line_crlf("HELO smtp_tester.py");
        s.read_line()
        s.send_line_crlf("MAIL FROM: <"+ mail_from +">");
        s.read_line()
        s.send_line_crlf("RCPT TO: <"+ rcpt_to +">");
        s.disconnect()

    def disconnect_after_data(self, mail_from, rcpt_to):
        s = SMTPConnection(self.host, self.port)
        s.connect()
        s.read_line()
        s.send_line_crlf("HELO smtp_tester.py");
        s.read_line()
        s.send_line_crlf("MAIL FROM: <"+ mail_from +">");
        s.read_line()
        s.send_line_crlf("RCPT TO: <"+ rcpt_to +">");
        s.read_line()
        s.send_line_crlf("DATA");
        s.read_line()
        s.disconnect()

    def disconnect_in_data(self, mail_from, rcpt_to):
        s = SMTPConnection(self.host, self.port)
        s.connect()
        s.read_line()
        s.send_line_crlf("HELO smtp_tester.py");
        s.read_line()
        s.send_line_crlf("MAIL FROM: <"+ mail_from +">");
        s.read_line()
        s.send_line_crlf("RCPT TO: <"+ rcpt_to +">");
        s.read_line()
        s.send_line_crlf("DATA");
        s.read_line()
        s.send_line_crlf("a"*100);
        s.disconnect()

    def disconnect_after_end_of_data(self, mail_from, rcpt_to):
        s = SMTPConnection(self.host, self.port)
        s.connect()
        s.read_line()
        s.send_line_crlf("HELO smtp_tester.py");
        s.read_line()
        s.send_line_crlf("MAIL FROM: <"+ mail_from +">");
        s.read_line()
        s.send_line_crlf("RCPT TO: <"+ rcpt_to +">");
        s.read_line()
        s.send_line_crlf("DATA");
        s.read_line()
        s.send_line_crlf("a"*100);
        s.send_line_crlf(".");
        s.disconnect()

    def disconnect_after_quit(self, mail_from, rcpt_to):
        s = SMTPConnection(self.host, self.port)
        s.connect()
        s.read_line()
        s.send_line_crlf("HELO smtp_tester.py");
        s.read_line()
        s.send_line_crlf("MAIL FROM: <"+ mail_from +">");
        s.read_line()
        s.send_line_crlf("RCPT TO: <"+ rcpt_to +">");
        s.read_line()
        s.send_line_crlf("DATA");
        s.read_line()
        s.send_line_crlf("a"*100);
        s.send_line_crlf(".");
        s.read_line()
        s.send_line_crlf("QUIT");
        s.disconnect()

    def thread_wrap(self, x, y, z):
        x(y, z)
        self.thread_lock.acquire()
        self.thread_count = self.thread_count - 1
        self.thread_lock.release()

    def test(self, mail_from, rcpt_to, tests, randomize=False, iterations=1, threads=10):
        self.thread_count = 0;
        self.thread_lock  = thread.allocate_lock()

        for i in range(0, threads):
            thread_tests = copy.deepcopy(tests)
            if randomize:
                random.shuffle(thread_tests)
            for j in range(0, iterations):
                for test in thread_tests:
                    x = getattr(self, test)
                    self.thread_lock.acquire()
                    self.thread_count = self.thread_count + 1
                    self.thread_lock.release()
                    thread.start_new_thread(self.thread_wrap, (x, mail_from, rcpt_to))
            ocount = self.thread_count
            while True:
                if self.thread_count == 0:
                    break
                print("."),
                time.sleep(1)
                sys.stdout.flush()


if __name__ == "__main__":

    tests = [ "sane",
              "connect_disconnect",
              "disconnect_after_banner",
              "disconnect_after_mail_from",
              "disconnect_after_rcpt_to",
              "disconnect_after_data",
              "disconnect_in_data",
              "disconnect_after_end_of_data",
              "disconnect_after_quit" ]
    
    tester = SMTPTester("localhost", 25)
    tester.test(sys.argv[1], sys.argv[2], tests, randomize=True, iterations=10, threads=20)
