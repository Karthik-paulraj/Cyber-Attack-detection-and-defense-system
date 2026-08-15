from collections import defaultdict

class PortScanDetector:
    def __init__(self, threshold=10):
        self.ip_ports = defaultdict(set)
        self.alerted = set()
        self.threshold = threshold
        self.seen_probes = set()

    def detect(self, source_ip, destination_ip, destination_port, source_port=None):
        if source_ip in self.alerted:
            return False

        if source_port is not None:
            if (destination_ip, source_ip, source_port) in self.seen_probes:
                return False
            self.seen_probes.add((source_ip, destination_ip, destination_port))

        self.ip_ports[source_ip].add(destination_port)

        if len(self.ip_ports[source_ip]) > self.threshold:
            self.alerted.add(source_ip)
            return True

        return False
