from analyser.parser import read_log_file, parse_log_entry
from analyser.detector import (
    detect_brute_force,
    detect_success_after_failures
)


def main():
    logs = read_log_file("logs/sample_auth.log")

    parsed_logs = [parse_log_entry(log) for log in logs]

    print("=" * 55)
    print("SentrySec Security Report")
    print("=" * 55)

    brute_force_alerts = detect_brute_force(parsed_logs)
    compromise_alerts = detect_success_after_failures(parsed_logs)

    print("\n=== Brute Force Detection ===")

    if brute_force_alerts:
        for alert in brute_force_alerts:
            print(alert)
    else:
        print("No brute-force attacks detected.")

    print("\n=== Account Compromise Detection ===")

    if compromise_alerts:
        for alert in compromise_alerts:
            print(alert)
    else:
        print("No suspicious successful logins detected.")


if __name__ == "__main__":
    main()