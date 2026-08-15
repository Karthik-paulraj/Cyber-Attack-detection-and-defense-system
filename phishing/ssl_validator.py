import ssl
import socket
from urllib.parse import urlparse

class SSLValidator:
    def __init__(self, timeout=5):
        self.timeout = timeout

    def analyze(self, url):
        score = 0
        reasons = []

        parsed = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
        hostname = parsed.hostname

        if not hostname:
            return score, reasons

        if parsed.scheme == "http":
            score += 20
            reasons.append("URL does not use HTTPS")
            return score, reasons

        is_valid, failure_reason = self._has_valid_certificate(hostname)

        if not is_valid:
            score += 20
            reasons.append(f"SSL certificate issue: {failure_reason}")

        return score, reasons

    def _has_valid_certificate(self, hostname):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                    secure_sock.getpeercert()
            return True, None

        except ssl.SSLCertVerificationError as error:
            return False, str(error.verify_message)

        except ssl.SSLError as error:
            return False, f"SSL error: {error}"

        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as error:
            return False, f"Connection failed: {error}"
