from flask import Flask, jsonify, render_template
import json

app = Flask(__name__)


def load_report():
    with open("security_report.json", "r") as file:
        return json.load(file)

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/")
def home():
    return "Security Dashboard API Running"


@app.route("/report")
def report():
    data = load_report()
    return jsonify(data)


@app.route("/alerts")
def alerts():
    data = load_report()

    return jsonify(
        data["suspicious_ips"]
    )


if __name__ == "__main__":
    app.run(debug=True)

    