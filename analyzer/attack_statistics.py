from collections import Counter


class TrafficStatistics:

    def __init__(self):

        self.counter = Counter()

    def add(self, protocol):

        self.counter[protocol] += 1

    def show(self):

        print("\n" + "=" * 60)
        print("TRAFFIC STATISTICS")
        print("=" * 60)

        for protocol, count in self.counter.items():

            print(f"{protocol:<10} : {count}")

        print("=" * 60)
