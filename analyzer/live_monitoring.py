from scapy.all import sniff
from detector import ThreatDetector

threat_detector = ThreatDetector()

def handle_packet(packet):
    alerts = threat_detector.process_packet(packet)

    for attack_type, ip in alerts:
        print(f"[ALERT] {attack_type} detected from {ip}")

def start_monitoring(interface=None):
    print("Starting live monitoring...")
    sniff(iface=interface, prn=handle_packet, store=False)

if __name__ == "__main__":
    start_monitoring()
