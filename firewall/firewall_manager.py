from firewall.rule_generator import RuleGenerator
from firewall.whitelist import Whitelist
from firewall.blacklist import Blacklist
from firewall.pending_review import PendingReview

class FirewallManager:
    def __init__(self):
        self.rule_generator = RuleGenerator()
        self.whitelist = Whitelist()
        self.blacklist = Blacklist()
        self.pending_review = PendingReview()

        self.auto_block_attacks = {
            "SYN_FLOOD",
            "ICMP_FLOOD",
            "UDP_FLOOD",
        }

        self.manual_confirm_attacks = {
            "PORT_SCAN",
            "SSH_BRUTEFORCE",
        }

    def handle_alert(self, attack_type, ip_address):
        if self.rule_generator.is_blocked(ip_address):
            return False

        if self.whitelist.is_whitelisted(ip_address):
            print(f"[FIREWALL] {ip_address} is whitelisted. Ignoring alert.")
            return False

        if self.blacklist.is_blacklisted(ip_address):
            print(f"[FIREWALL] {ip_address} is blacklisted. Blocking immediately.")
            self.rule_generator.block_ip(ip_address)
            return True

        if attack_type in self.auto_block_attacks:
            print(f"[FIREWALL] {attack_type} from {ip_address}. Auto-blocking.")
            self.rule_generator.block_ip(ip_address)
            return True

        if attack_type in self.manual_confirm_attacks:
            print(f"[FIREWALL] {attack_type} from {ip_address}. Recommended for review.")
            self.pending_review.add(ip_address, attack_type)
            return False

        return False
