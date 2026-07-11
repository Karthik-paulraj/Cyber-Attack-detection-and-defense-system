from scapy.layers.inet import IP, TCP
from models import PortTracker

tracker = PortTracker()

class ThreatDetector:

  def detect(self, packet):

    if not packet.haslayer(IP):
        return

    if not packet.haslayer(TCP):
        return

    ip = packet[IP]
    tcp = packet[TCP]

    tracker.add(ip.src, tcp.dport)

    if tracker.count(ip.src) > 2:

        print("="*50)
        print("🚨 PORT SCAN DETECTED")
        print("Source :", ip.src)
        print("Ports  :", tracker.count(ip.src))
        print("="*50)
