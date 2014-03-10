function on_connect(id, localip, remoteip, hostname)
   print("####### IN LUA: on connect")
   print("local: " .. localip)
   print("remote:  " .. remoteip)
   print("hostname: " .. hostname)
   filter.accept(id)
end

function on_helo(id, helo)
    print("####### IN LUA: on helo")
    if helo == "reject" then
        print("will reject")
        filter.reject(id, filter.FILTER_CLOSE)
	return
     end
    print("will accept")
    filter.accept(id)
end

function on_mail(id, sender)
   print("####### IN LUA: on mail")
   print("will accept sender: " .. sender)
   filter.accept(id)
end

function on_rcpt(id, rcpt)
   print("####### IN LUA: on rcpt")
   print("will accept recipient: " .. rcpt)
   filter.accept(id)
end

function on_data(id)
   print("####### IN LUA: on data")
   filter.accept(id)
end

function on_eom(id)
   print("####### IN LUA: on data")
   filter.accept(id)
end

function on_disconnect(id)
   print("####### IN LUA: on disconnect")
   filter.accept(id)
end
