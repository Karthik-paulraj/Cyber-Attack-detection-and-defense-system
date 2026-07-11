from collections import defaultdict

class PortTracker:

    def __init__(self):

        self.connections = defaultdict(set)

    def add(self, src, port):

        self.connections[src].add(port)

    def count(self, src):

        return len(self.connections[src])
