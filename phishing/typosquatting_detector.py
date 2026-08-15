import csv
import os
from urllib.parse import urlparse

class TyposquattingDetector:
    def __init__(self, domain_list_path=None):
        if domain_list_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            domain_list_path = os.path.join(base_dir, "data", "top_domains.csv")

        self.known_brands = self._load_domains(domain_list_path)
        self.max_edit_distance = 2
        self.length_filter_margin = 3

    def _load_domains(self, filepath):
        domains = []

        if not os.path.exists(filepath):
            print(f"[TyposquattingDetector] Warning: file not found at {filepath}")
            return domains

        with open(filepath, "r", encoding="utf-8-sig") as file:
            reader = csv.reader(file)

            for row in reader:
                if len(row) < 2:
                    continue

                rank = row[0].strip()
                domain = row[1].strip().lower()

                if not rank.isdigit():
                    continue

                if domain:
                    domains.append(domain)

        return domains

    def analyze(self, url):
        score = 0
        reasons = []

        hostname = self._get_hostname(url)

        if not hostname:
            return score, reasons

        candidates = self._get_candidates(hostname)

        for brand in candidates:
            if hostname == brand:
                continue

            distance = self._edit_distance(hostname, brand)

            if distance <= self.max_edit_distance:
                score += 30
                reasons.append(f"Domain '{hostname}' closely resembles known brand '{brand}' (edit distance: {distance})")
                break

        return score, reasons

    def _get_candidates(self, hostname):
        candidates = []

        for brand in self.known_brands:
            if abs(len(brand) - len(hostname)) <= self.length_filter_margin:
                candidates.append(brand)

        return candidates

    def _get_hostname(self, url):
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        return hostname.lower()

    def _edit_distance(self, first_word, second_word):
        rows = len(first_word) + 1
        columns = len(second_word) + 1

        table = [[0] * columns for _ in range(rows)]

        for row in range(rows):
            table[row][0] = row

        for column in range(columns):
            table[0][column] = column

        for row in range(1, rows):
            for column in range(1, columns):
                if first_word[row - 1] == second_word[column - 1]:
                    cost = 0
                else:
                    cost = 1

                table[row][column] = min(
                    table[row - 1][column] + 1,
                    table[row][column - 1] + 1,
                    table[row - 1][column - 1] + cost,
                )

        return table[rows - 1][columns - 1]
