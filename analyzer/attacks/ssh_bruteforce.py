from collections import Counter
from scapy.all import TCP

class SSHBruteForceDetector:
    def __init__(self, threshold=5):
        self.attempt_counts = Counter()
        self.alerted = set()
        self.threshold = threshold
        self.ssh_port = 22

    def detect(self, packet):
        if not packet.haslayer(TCP):
            return False

        if packet[TCP].dport != self.ssh_port:
            return False

        if packet[TCP].flags != "S":
            return False

        source_ip = packet[0][1].src

        if source_ip in self.alerted:
            return False

        self.attempt_counts[source_ip] += 1

        if self.attempt_counts[source_ip] > self.threshold:
            self.alerted.add(source_ip)
            return True

        return False
