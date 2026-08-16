import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import sniff
from detector import ThreatDetector
from firewall.firewall_manager import FirewallManager
from malware.malware_detector import MalwareDetector

threat_detector = ThreatDetector()
firewall_manager = FirewallManager()
malware_detector = MalwareDetector()

def handle_packet(packet):
    alerts = threat_detector.process_packet(packet)

    for attack_type, ip in alerts:
        print(f"[ALERT] {attack_type} detected from {ip}")
        firewall_manager.handle_alert(attack_type, ip)

    malware_alerts = malware_detector.process_packet(packet)

    for attack_type, ip, indicator, reasons in malware_alerts:
        print(f"[MALWARE ALERT] {attack_type} from {ip} — {indicator}")
        for reason in reasons:
            print(f"  - {reason}")

def start_monitoring(interfaces=None):
    print("Starting live monitoring...")
    sniff(iface=interfaces, prn=handle_packet, store=False)

if __name__ == "__main__":
    start_monitoring(interfaces=["eth0", "lo"])
