from collections import defaultdict


def detect_brute_force(parsed_logs, threshold=3):
    """
    Detect brute-force attacks based on failed login attempts per IP.
    """

    failed_counts = defaultdict(int)
    last_failed_event = {}

    for event in parsed_logs:

        if event["status"] == "Failed":

            ip = event["ip"]

            failed_counts[ip] += 1

            # Keep the timestamp of the latest failed attempt
            last_failed_event[ip] = event["timestamp"]

    alerts = []

    for ip, count in failed_counts.items():

        if count >= threshold:

            alerts.append({
                "type": "SSH Brute Force",
                "severity": "HIGH",
                "ip": ip,
                "attempts": count,
                "timestamp": last_failed_event[ip]
            })

    return alerts


def detect_success_after_failures(parsed_logs, threshold=3):
    """
    Detect successful logins after multiple failed attempts.
    """

    failed_counts = defaultdict(int)
    alerts = []

    # Count failures
    for event in parsed_logs:

        if event["status"] == "Failed":

            key = (event["ip"], event["username"])

            failed_counts[key] += 1

    # Look for a success after enough failures
    for event in parsed_logs:

        if event["status"] == "Success":

            key = (event["ip"], event["username"])

            if failed_counts[key] >= threshold:

                alerts.append({
                    "type": "Possible Account Compromise",
                    "severity": "CRITICAL",
                    "ip": event["ip"],
                    "username": event["username"],
                    "failed_attempts": failed_counts[key],
                    "timestamp": event["timestamp"]
                })

    return alerts