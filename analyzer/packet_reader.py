from scapy.all import rdpcap

from detector import ThreatDetector
from detector import stats
from detector import host_tracker
from detector import tracker


def main():

    packets = rdpcap("../captures/network_capture.pcap")

    detector = ThreatDetector()

    print("=" * 60)
    print("Cyber Attack Detection and Defense System")
    print("=" * 60)
    print(f"Packets Loaded : {len(packets)}")
    print("=" * 60)

    for packet in packets:

        detector.detect(packet)

    stats.show()

    host_tracker.show()

    tracker.show()


if __name__ == "__main__":

    main()
