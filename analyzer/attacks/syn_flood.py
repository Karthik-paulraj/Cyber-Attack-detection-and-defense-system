from collections import Counter
from scapy.all import TCP

class SynFloodDetector:
    def __init__(self, threshold=100):
        self.syn_counts = Counter()
        self.alerted = set()
        self.threshold = threshold

    def detect(self, packet):
        if not packet.haslayer(TCP):
            return False

        if packet[TCP].flags != "S":
            return False

        source_ip = packet[0][1].src

        if source_ip in self.alerted:
            return False

        self.syn_counts[source_ip] += 1

        if self.syn_counts[source_ip] > self.threshold:
            self.alerted.add(source_ip)
            return True

        return False
