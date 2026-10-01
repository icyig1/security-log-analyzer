import json
import os
from pathlib import Path

from flask import Flask, jsonify, render_template

app = Flask(__name__)

# Same default location the analyzer writes to; override with REPORT_PATH.
REPORT_PATH = Path(os.environ.get("REPORT_PATH", Path(__file__).with_name("security_report.json")))


def load_report():
    """Return (report, error_response). Exactly one of them is None."""
    try:
        with open(REPORT_PATH, "r", encoding="utf-8") as file:
            return json.load(file), None
    except FileNotFoundError:
        message = "No report yet. Run log_analyzer.py first."
        return None, (jsonify({"error": message}), 404)
    except json.JSONDecodeError:
        return None, (jsonify({"error": "Report is being written. Try again."}), 503)


@app.route("/")
def home():
    return "Security Dashboard API Running"


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/report")
def report():
    data, error = load_report()
    return error or jsonify(data)


@app.route("/alerts")
def alerts():
    data, error = load_report()
    return error or jsonify(data["suspicious_ips"])


if __name__ == "__main__":
    app.run(debug=True)
