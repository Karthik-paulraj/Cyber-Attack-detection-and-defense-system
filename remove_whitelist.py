from firewall.whitelist import Whitelist

wl = Whitelist()

ip_addr = ["10.0.2.2","10.0.2.15"]

for i in ip_addr:
    wl.remove(i)


