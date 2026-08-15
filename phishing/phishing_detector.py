import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishing.url_analyzer import URLAnalyzer
from phishing.keyword_detector import KeywordDetector
from phishing.typosquatting_detector import TyposquattingDetector
from phishing.ssl_validator import SSLValidator
from phishing.risk_scorer import RiskScorer

class PhishingDetector:
    def __init__(self):
        self.url_analyzer = URLAnalyzer()
        self.keyword_detector = KeywordDetector()
        self.typosquatting_detector = TyposquattingDetector()
        self.ssl_validator = SSLValidator()
        self.risk_scorer = RiskScorer()

        self.trust_reduction_factor = 0.2

    def check_url(self, url):
        total_score = 0
        all_reasons = []

        modules = [
            self.url_analyzer,
            self.keyword_detector,
            self.typosquatting_detector,
            self.ssl_validator,
        ]

        for module in modules:
            score, reasons = module.analyze(url)
            total_score += score
            all_reasons.extend(reasons)

        if self._is_trusted_domain(url):
            reduced_score = round(total_score * self.trust_reduction_factor)
            all_reasons.append(
                f"Domain is a known trusted domain with valid SSL — score reduced from {total_score} to {reduced_score}"
            )
            total_score = reduced_score

        risk_level = self.risk_scorer.calculate_risk(total_score)

        return {
            "url": url,
            "score": total_score,
            "risk_level": risk_level,
            "reasons": all_reasons,
        }

    def _is_trusted_domain(self, url):
        hostname = self.typosquatting_detector._get_hostname(url)

        is_known = hostname in self.typosquatting_detector.known_brands
        is_subdomain_of_known = any(
            hostname.endswith("." + brand) for brand in self.typosquatting_detector.known_brands
        )

        if not (is_known or is_subdomain_of_known):
            return False

        ssl_score, _ = self.ssl_validator.analyze(url)

        return ssl_score == 0


if __name__ == "__main__":
    detector = PhishingDetector()

    test_urls = [
        "https://www.google.com",
        "http://192.168.1.5/verify-account",
        "http://paypa1.com/secure-login-verify",
        "https://accounts.google.com/signin",
    ]

    for url in test_urls:
        result = detector.check_url(url)
        print(f"\nURL: {result['url']}")
        print(f"Score: {result['score']} — Risk: {result['risk_level']}")
        for reason in result['reasons']:
            print(f"  - {reason}")
