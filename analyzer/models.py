from collections import defaultdict


class PortTracker:

    def __init__(self):

        self.connections = defaultdict(set)

    def add(self, source_ip, destination_port):

        self.connections[source_ip].add(destination_port)

    def count(self, source_ip):
        return len(self.connections[source_ip])

    def show(self):
        print(self.connections)

