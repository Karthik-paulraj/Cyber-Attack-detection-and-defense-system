from rule_generator import RuleGenerator
from pending_review import PendingReview

def review_blocked_ips():
    rg = RuleGenerator()
    blocked_ips = rg.list_blocked()

    print("=== Currently Blocked IPs ===")
    if not blocked_ips:
        print("None.")
    else:
        for index, ip in enumerate(blocked_ips, start=1):
            print(f"{index}. {ip}")

        choice = input("Enter a number to unblock (or press Enter to skip): ")
        if choice.strip() != "":
            try:
                selected_ip = blocked_ips[int(choice) - 1]
                rg.unblock_ip(selected_ip)
                print(f"Unblocked: {selected_ip}")
            except (ValueError, IndexError):
                print("Invalid selection.")

    print()
    print("=== Pending Review (recommended blocks) ===")
    pr = PendingReview()
    pending = pr.list_pending()

    if not pending:
        print("None.")
        return

    pending_list = list(pending.items())
    for index, (ip, attack_type) in enumerate(pending_list, start=1):
        print(f"{index}. {ip} — flagged for {attack_type}")

    choice = input("Enter a number to block that IP (or press Enter to skip): ")
    if choice.strip() == "":
        return

    try:
        selected_ip, attack_type = pending_list[int(choice) - 1]
        rg.block_ip(selected_ip)
        pr.remove(selected_ip)
        print(f"Blocked: {selected_ip}")
    except (ValueError, IndexError):
        print("Invalid selection.")

if __name__ == "__main__":
    review_blocked_ips()
