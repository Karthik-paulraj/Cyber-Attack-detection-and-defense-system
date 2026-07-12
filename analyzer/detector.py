from scapy.layers.inet import IP, TCP, UDP, ICMP

from models import PortTracker
from statistics import TrafficStatistics
from host_tracker import HostTracker


tracker = PortTracker()
stats = TrafficStatistics()
host_tracker = HostTracker()


class ThreatDetector:

    def detect(self, packet):

        # Ignore non-IPv4 packets
        if not packet.haslayer(IP):
            return

        ip = packet[IP]

        # -------------------------
        # TCP
        # -------------------------
        if packet.haslayer(TCP):

            tcp = packet[TCP]

            stats.add("TCP")

            host_tracker.add(
                ip.src,
                ip.dst,
                tcp.dport
            )

            tracker.add(
                ip.src,
                tcp.dport
            )

            if tracker.count(ip.src) > 10:

                print("\n" + "=" * 60)
                print("🚨 POSSIBLE PORT SCAN DETECTED")
                print("=" * 60)
                print(f"Source IP       : {ip.src}")
                print(f"Destination IP  : {ip.dst}")
                print(f"Unique Ports    : {tracker.count(ip.src)}")
                print("=" * 60)

        # -------------------------
        # UDP
        # -------------------------
        elif packet.haslayer(UDP):

            udp = packet[UDP]

            stats.add("UDP")

            host_tracker.add(
                ip.src,
                ip.dst,
                udp.dport
            )

        # -------------------------
        # ICMP
        # -------------------------
        elif packet.haslayer(ICMP):

            stats.add("ICMP")

            host_tracker.add(
                ip.src,
                ip.dst,
                0
            )

        # -------------------------
        # Other IP protocols
        # -------------------------
        else:

            stats.add("OTHER")
