from scapy.all import rdpcap
from detector import ThreatDetector

packets = rdpcap("../captures/network_capture.pcap")

detector = ThreatDetector()

print(f"Loaded {len(packets)} packets\n")

for packet in packets:

    detector.detect(packet)
