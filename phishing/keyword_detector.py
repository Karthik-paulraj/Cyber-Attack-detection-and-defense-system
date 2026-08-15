class KeywordDetector:
    def __init__(self):
        self.suspicious_keywords = [
            "login", "verify", "secure", "account", "update",
            "confirm", "bank", "signin", "password", "urgent",
            "suspended", "limited", "click", "billing",
        ]
        self.points_per_keyword = 8
        self.max_score = 40

    def analyze(self, url):
        score = 0
        reasons = []

        lowered_url = url.lower()

        for keyword in self.suspicious_keywords:
            if keyword in lowered_url:
                score += self.points_per_keyword
                reasons.append(f"Contains suspicious keyword: '{keyword}'")

        score = min(score, self.max_score)

        return score, reasons
