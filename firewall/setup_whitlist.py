from whitelist import Whitelist

def setup_default_whitelist():
    wl = Whitelist()

    default_safe_ips = [
        "192.168.56.102",
        "192.168.56.1",
        "127.0.0.1",
    ]

    for ip in default_safe_ips:
        wl.add(ip)
        print(f"Whitelisted: {ip}")

    print("Setup complete. Current whitelist:")
    print(wl.whitelisted_ips)

if __name__ == "__main__":
    setup_default_whitelist()
