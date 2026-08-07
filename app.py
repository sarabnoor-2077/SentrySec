from flask import Flask, render_template, request
import os

from analyser.parser import read_log_file, parse_log_entry
from analyser.detector import (
    detect_brute_force,
    detect_success_after_failures
)

from database import (
    initialize_database,
    save_scan,
    save_threat,
    get_history,
    get_statistics,
    get_chart_data,
    get_scan,
    get_threats
)

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Create the SQLite database (only if it doesn't already exist)
initialize_database()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    file = request.files["logfile"]

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)

    file.save(filepath)

    logs = read_log_file(filepath)

    parsed_logs = [parse_log_entry(log) for log in logs]

    brute_force = detect_brute_force(parsed_logs)

    compromise = detect_success_after_failures(parsed_logs)

    total_logs = len(parsed_logs)

    failed = sum(1 for e in parsed_logs if e["status"] == "Failed")

    success = sum(1 for e in parsed_logs if e["status"] == "Success")

    threat_count = len(brute_force) + len(compromise)

    # Save this scan and get its ID
    scan_id = save_scan(
        file.filename,
        total_logs,
        failed,
        success,
        threat_count
    )

    # Save brute force alerts
    for alert in brute_force:

        save_threat(
            scan_id,
            alert["severity"],
            alert["type"],
            alert["ip"],
            "N/A"  # No specific log time for brute force alerts
        )

    # Save compromise alerts
    for alert in compromise:

        save_threat(
            scan_id,
            alert["severity"],
            alert["type"],
            alert["ip"],
            "N/A"  # No specific log time for compromise alerts
        )

    return render_template(
        "results.html",
        brute_force=brute_force,
        compromise=compromise,
        total_logs=total_logs,
        failed=failed,
        success=success
    )

@app.route("/history")
def history():

    scans = get_history()

    return render_template(
        "history.html",
        scans=scans
    )

@app.route("/analytics")
def analytics():

    stats = get_statistics()

    labels, threats = get_chart_data()

    return render_template(
        "analytics.html",
        stats=stats,
        labels=labels,
        threats=threats
    )

@app.route("/scan/<int:scan_id>")
def scan_details(scan_id):

    scan = dict(get_scan(scan_id))   # <-- change this line

    threats = [dict(t) for t in get_threats(scan_id)]

    return render_template(
        "scan_details.html",
        scan=scan,
        threats=threats
    )

if __name__ == "__main__":
    app.run(debug=True)