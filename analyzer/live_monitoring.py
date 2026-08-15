import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import sniff
from detector import ThreatDetector
from firewall.firewall_manager import FirewallManager
threat_detector = ThreatDetector()
firewall_manager = FirewallManager()

def handle_packet(packet):
    alerts = threat_detector.process_packet(packet)

    for attack_type, ip in alerts:
        print(f"[ALERT] {attack_type} detected from {ip}")
        firewall_manager.handle_alert(attack_type, ip)

def start_monitoring(interfaces=None):
    print("Starting live monitoring...")
    sniff(iface=interfaces, prn=handle_packet, store=False)

if __name__ == "__main__":
    start_monitoring(interfaces=["eth0", "lo"])
