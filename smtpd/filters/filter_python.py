import filter

def on_connect(id, local, remote, hostname):
    print("####### IN PYTHON: on connect")
    print("local: "+local)
    print("remote:  "+remote)
    print("hostname: "+hostname)
    return filter.accept(id)

def on_helo(id, heloname):
    print("####### IN PYTHON: on helo")
    if "reject" in heloname:
        print("will reject")
        return filter.reject(id)
    print("will accept")
    return filter.accept(id)

def on_mail(id, sender):
    print("####### IN PYTHON: on mail")
    print("will accept sender: "+sender)
    return filter.accept(id)


def on_rcpt(id, recipient):
    print("####### IN PYTHON: on rcpt")
    print("will accept recipient: "+recipient)
    return filter.accept(id)


def on_data(id):
    print("####### IN PYTHON: on data")
    return filter.accept(id)

def on_eom(id):
    print("####### IN PYTHON: on eom")
    return filter.accept(id)

def on_commit(id):
    print("####### IN PYTHON: on commit")
    pass

def on_disconnect(id):
    print("####### IN PYTHON: on disconnect")
    pass


def on_dataline(id, line):
    filter.writeln(id, line)
    filter.writeln(id, line.upper())

