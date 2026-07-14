from flask import Flask
from flask import jsonify

app = Flask(__name__)

@app.route("/alerts")
def alerts():

    with open("security_report.json") as f:

        report = json.load(f)

    return jsonify(report["suspicious_ips"])