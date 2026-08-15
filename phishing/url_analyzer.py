from urllib.parse import urlparse

class URLAnalyzer:
    def __init__(self):
        self.max_normal_length = 75
        self.max_normal_subdomains = 3

    def analyze(self, url):
        score = 0
        reasons = []

        normalized_url = self._normalize(url)
        parsed = urlparse(normalized_url)
        hostname = parsed.hostname or ""

        if self._is_ip_address(hostname):
            score += 25
            reasons.append("URL uses a raw IP address instead of a domain name")

        if "@" in normalized_url:
            score += 25
            reasons.append("URL contains an '@' symbol")

        subdomain_count = hostname.count(".")
        if subdomain_count > self.max_normal_subdomains:
            score += 15
            reasons.append(f"URL has an unusually high number of subdomains ({subdomain_count})")

        if len(url) > self.max_normal_length:
            score += 10
            reasons.append(f"URL is unusually long ({len(url)} characters)")

        return score, reasons

    def _normalize(self, url):
        if not url.startswith(("http://", "https://")):
            return "http://" + url
        return url

    def _is_ip_address(self, hostname):
        parts = hostname.split(".")

        if len(parts) != 4:
            return False

        for part in parts:
            if not part.isdigit():
                return False
            if not 0 <= int(part) <= 255:
                return False

        return True
