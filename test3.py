from firewall.whitelist import Whitelist

wl = Whitelist()

print(wl.is_whitelisted("10.0.2.15"))
