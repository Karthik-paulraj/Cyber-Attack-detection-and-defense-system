class RiskScorer:
    def __init__(self):
        self.low_threshold = 20
        self.medium_threshold = 50

    def calculate_risk(self, total_score):
        if total_score <= self.low_threshold:
            return "LOW"
        elif total_score <= self.medium_threshold:
            return "MEDIUM"
        else:
            return "HIGH"
