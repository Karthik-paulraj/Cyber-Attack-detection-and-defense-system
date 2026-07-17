from collections import Counter
from scapy.all import UDP

class UDPFloodDetector:
    def __init__(self, threshold=100):
        self.udp_counts = Counter()
        self.alerted = set()
        self.threshold = threshold

    def detect(self, packet):
        if not packet.haslayer(UDP):
            return False

        source_ip = packet[0][1].src

        if source_ip in self.alerted:
            return False

        self.udp_counts[source_ip] += 1

        if self.udp_counts[source_ip] > self.threshold:
            self.alerted.add(source_ip)
            return True

