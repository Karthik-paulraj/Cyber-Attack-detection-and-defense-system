import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishing.phishing_detector import PhishingDetector

detector = PhishingDetector()

test_cases = {
    "Legitimate, well-known": [
        "https://www.google.com",
        "https://www.amazon.com",
        "https://www.microsoft.com",
    ],
    "Legitimate with auth-related paths": [
        "https://accounts.google.com/signin",
        "https://www.paypal.com/myaccount/login",
        "https://www.amazon.com/gp/css/order-history",
    ],
    "IP address URLs": [
        "http://192.168.1.5/login",
        "http://45.33.32.156/verify-account",
    ],
    "Typosquatted domains": [
        "http://paypa1.com",
        "http://gooogle.com",
        "http://amaz0n.com",
        "http://faceb00k.com",
    ],
    "Keyword-stuffed, unrelated domain": [
        "http://secure-account-verify-update-login.ru",
    ],
    "Combined attack (realistic phishing)": [
        "http://paypa1-secure-verify-account.ru/login",
        "http://192.168.1.5/paypal-account-verify-urgent",
    ],
    "Edge case: legitimate but likely not in top 10k": [
        "https://www.tranco-list.eu",
    ],
}

for category, urls in test_cases.items():
    print(f"\n{'=' * 60}")
    print(f"CATEGORY: {category}")
    print('=' * 60)

    for url in urls:
        result = detector.check_url(url)
        print(f"\nURL: {result['url']}")
        print(f"Score: {result['score']} — Risk: {result['risk_level']}")
        for reason in result['reasons']:
            print(f"  - {reason}")
