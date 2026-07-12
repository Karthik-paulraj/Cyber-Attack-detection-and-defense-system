from collections import Counter


class HostTracker:

    def __init__(self):

        self.source_counter = Counter()
        self.destination_counter = Counter()
        self.port_counter = Counter()

    def add(self, src, dst, port):

        self.source_counter[src] += 1
        self.destination_counter[dst] += 1
        self.port_counter[port] += 1

    def show(self):

        print("\n" + "=" * 60)
        print("HOST STATISTICS")
        print("=" * 60)

        print("\nTop Source IPs")
	
        for ip, count in self.source_counter.most_common(5):

            print(f"{ip:<20} {count}")
            
        print("\nTop Destination IPs")

        for ip, count in self.destination_counter.most_common(5):

            print(f"{ip:<20} {count}")

        print("\nTop Destination Ports")

        for port, count in self.port_counter.most_common(10):

            print(f"{port:<10} {count}")
