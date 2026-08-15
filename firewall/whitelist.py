import json
import os

class Whitelist:
    def __init__(self, filepath="firewall/whitelist.json"):
        self.filepath = filepath
        self.whitelisted_ips = self._load()

    def _load(self):
        if not os.path.exists(self.filepath):
            return set()

        with open(self.filepath, "r") as file:
            data = json.load(file)
            return set(data)

    def _save(self):
        with open(self.filepath, "w") as file:
            json.dump(list(self.whitelisted_ips), file, indent=2)

    def add(self, ip_address):
        self.whitelisted_ips.add(ip_address)
        self._save()

    def remove(self, ip_address):
        self.whitelisted_ips.discard(ip_address)
        self._save()

    def is_whitelisted(self, ip_address):
        return ip_address in self.whitelisted_ips
