import json
import os

class PendingReview:
    def __init__(self, filepath="firewall/pending_review.json"):
        self.filepath = filepath
        self.pending = self._load()

    def _load(self):
        if not os.path.exists(self.filepath):
            return {}

        with open(self.filepath, "r") as file:
            return json.load(file)

    def _save(self):
        with open(self.filepath, "w") as file:
            json.dump(self.pending, file, indent=2)

    def add(self, ip_address, attack_type):
        self.pending[ip_address] = attack_type
        self._save()

    def remove(self, ip_address):
        if ip_address in self.pending:
            del self.pending[ip_address]
            self._save()

    def list_pending(self):
        return self.pending
