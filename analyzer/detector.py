from attacks.port_scan import PortScanDetector
from attacks.syn_flood import SynFloodDetector
from attacks.icmp_flood import ICMPFloodDetector
from attacks.udp_flood import UDPFloodDetector
from attacks.ssh_bruteforce import SSHBruteForceDetector

class ThreatDetector:
    def __init__(self):
        self.port_scan_detector = PortScanDetector()
        self.syn_flood_detector = SynFloodDetector()
        self.icmp_flood_detector = ICMPFloodDetector()
        self.udp_flood_detector = UDPFloodDetector()
        self.ssh_bruteforce_detector = SSHBruteForceDetector()

    def process_packet(self, packet):
        alerts = []

        if packet.haslayer("TCP") and packet["TCP"].flags == "S":
            source_ip = packet[0][1].src
            destination_ip = packet[0][1].dst
            destination_port = packet["TCP"].dport

            if self.port_scan_detector.detect(source_ip, destination_ip, destination_port):
                alerts.append(("PORT_SCAN", source_ip))

        elif packet.haslayer("UDP"):
            source_ip = packet[0][1].src
            destination_ip = packet[0][1].dst
            destination_port = packet["UDP"].dport
            source_port = packet["UDP"].sport

            if self.port_scan_detector.detect(source_ip, destination_ip, destination_port, source_port):
                alerts.append(("PORT_SCAN", source_ip))

        if self.syn_flood_detector.detect(packet):
            alerts.append(("SYN_FLOOD", packet[0][1].src))

        if self.icmp_flood_detector.detect(packet):
            alerts.append(("ICMP_FLOOD", packet[0][1].src))

        if self.udp_flood_detector.detect(packet):
            alerts.append(("UDP_FLOOD", packet[0][1].src))

        if self.ssh_bruteforce_detector.detect(packet):
            alerts.append(("SSH_BRUTEFORCE", packet[0][1].src))

        return alerts
