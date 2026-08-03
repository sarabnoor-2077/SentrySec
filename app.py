from flask import Flask, render_template, request
import os

from analyser.parser import read_log_file, parse_log_entry
from analyser.detector import (
    detect_brute_force,
    detect_success_after_failures
)

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


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

    return render_template(
        "results.html",
        brute_force=brute_force,
        compromise=compromise,
        total_logs=total_logs,
        failed=failed,
        success=success
    )

    
if __name__ == "__main__":
    app.run(debug=True)