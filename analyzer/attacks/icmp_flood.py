from collections import Counter
from scapy.all import ICMP

class ICMPFloodDetector:
    def __init__(self, threshold=50):
        self.icmp_counts = Counter()
        self.alerted = set()
        self.threshold = threshold

    def detect(self, packet):
        if not packet.haslayer(ICMP):
            return False

        source_ip = packet[0][1].src

        if source_ip in self.alerted:
            return False

        self.icmp_counts[source_ip] += 1

        if self.icmp_counts[source_ip] > self.threshold:
            self.alerted.add(source_ip)
            return True

        return False
