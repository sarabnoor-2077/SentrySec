from analyser.parser import read_log_file, parse_log_entry
from analyser.detector import detect_brute_force


def main():
    logs = read_log_file("logs/sample_auth.log")

    # Convert raw logs into structured events
    parsed_logs = [parse_log_entry(log) for log in logs]

    print("=" * 50)
    print("Parsed Events")
    print("=" * 50)

    for event in parsed_logs:
        print(event)

    print("\n" + "=" * 50)
    print("Security Report")
    print("=" * 50)

    alerts = detect_brute_force(parsed_logs)

    if not alerts:
        print("No brute-force attacks detected.")
    else:
        for alert in alerts:
            print(f"\nSeverity : {alert['severity']}")
            print(f"Attack   : {alert['type']}")
            print(f"IP       : {alert['ip']}")
            print(f"Attempts : {alert['attempts']}")


if __name__ == "__main__":
    main()