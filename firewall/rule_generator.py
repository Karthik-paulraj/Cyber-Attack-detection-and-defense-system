import subprocess

class RuleGenerator:
    def is_blocked(self, ip_address):
        command = ["sudo", "iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
        result = subprocess.run(command, capture_output=True)
        return result.returncode == 0

    def block_ip(self, ip_address):
        if self.is_blocked(ip_address):
            return False

        command = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
        subprocess.run(command)
        return True

    def unblock_ip(self, ip_address):
        if not self.is_blocked(ip_address):
            return False

        command = ["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
        subprocess.run(command)
        return True

    def list_blocked(self):
        command = ["sudo", "iptables", "-L", "INPUT", "-n"]
        result = subprocess.run(command, capture_output=True, text=True)

        blocked_ips = []
        for line in result.stdout.splitlines():
            if "DROP" in line:
                parts = line.split()
                source_ip = parts[3]
                blocked_ips.append(source_ip)

        return blocked_ips
