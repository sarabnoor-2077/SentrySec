from pathlib import Path
import re


def read_log_file(file_path):
    """
    Reads a log file and returns all lines as a list.
    """
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    with path.open("r", encoding="utf-8") as file:
        return [line.strip() for line in file if line.strip()]


def parse_log_entry(log):
    """
    Extracts important information from one SSH log entry.
    """

    event = {}

    # Timestamp
    event["timestamp"] = " ".join(log.split()[:3])

    # Status
    if "Failed password" in log:
        event["status"] = "Failed"
    elif "Accepted password" in log:
        event["status"] = "Success"
    else:
        event["status"] = "Unknown"

    # IP Address
    ip_match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", log)

    if ip_match:
        event["ip"] = ip_match.group(1)
    else:
        event["ip"] = "Unknown"

    # Username
    user_match = re.search(r"(?:invalid user )?(\w+) from", log)

    if user_match:
        event["username"] = user_match.group(1)
    else:
        event["username"] = "Unknown"

    return event