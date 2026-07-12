from scapy.layers.inet import IP, TCP, UDP, ICMP

from models import PortTracker
from statistics import TrafficStatistics
from host_tracker import HostTracker


# Create objects
tracker = PortTracker()
stats = TrafficStatistics()
host_tracker = HostTracker()


class ThreatDetector:

    def detect(self, packet):

        # Ignore packets without an IPv4 layer
        if not packet.haslayer(IP):
            return

        ip = packet[IP]

        # -------------------------------
        # TCP PACKETS
        # -------------------------------
        if packet.haslayer(TCP):

            tcp = packet[TCP]

            # Update statistics
            stats.add("TCP")

            # Update host information
            host_tracker.add(
                ip.src,
                ip.dst,
                tcp.dport
            )

            # Track unique destination ports
            tracker.add(
                ip.src,
                tcp.dport
            )
            

            # Port Scan Detection
            if tracker.count(ip.src) > 10:

                print("\n" + "=" * 60)
                print("🚨 POSSIBLE PORT SCAN DETECTED")
                print("=" * 60)
                print(f"Source IP        : {ip.src}")
                print(f"Destination IP   : {ip.dst}")
                print(f"Unique Ports     : {tracker.count(ip.src)}")
                print("=" * 60)

        # -------------------------------
        # UDP PACKETS
        # -------------------------------
        elif packet.haslayer(UDP):

            udp = packet[UDP]

            stats.add("UDP")

            host_tracker.add(
                ip.src,
                ip.dst,
                udp.dport
            )

        # -------------------------------
        # ICMP PACKETS
        # -------------------------------
        elif packet.haslayer(ICMP):

            stats.add("ICMP")

            # ICMP has no destination port
            host_tracker.add(
                ip.src,
                ip.dst,
                0
            )

        # -------------------------------
        # OTHER IP PROTOCOLS
        # -------------------------------
        else:

            stats.add("OTHER")

    
