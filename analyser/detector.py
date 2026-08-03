from collections import defaultdict


def detect_brute_force(parsed_logs, threshold=3):
    """
    Detects brute-force attacks based on failed login attempts per IP.
    """

    failed_counts = defaultdict(int)

    for event in parsed_logs:
        if event["status"] == "Failed":
            failed_counts[event["ip"]] += 1

    alerts = []

    for ip, count in failed_counts.items():
        if count >= threshold:
            alerts.append({
                "type": "SSH Brute Force",
                "severity": "HIGH",
                "ip": ip,
                "attempts": count
            })

    return alerts