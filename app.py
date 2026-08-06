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
    get_history,
    get_statistics
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

    # Save this scan to SQLite
    save_scan(
        file.filename,
        total_logs,
        failed,
        success,
        threat_count
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

    return render_template(
        "analytics.html",
        stats=stats
    )

if __name__ == "__main__":
    app.run(debug=True)