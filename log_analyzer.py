import re
import json
import time
import argparse
import bisect
from collections import defaultdict

# Match: time, user, ip
pattern = r"^\w+\s+\d+\s+(\d+:\d+:\d+).*Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)"

def stream_file(filename):
    with open(filename, "r") as file:
        file.seek(0, 2)  # go to end of file

        while True:
            line = file.readline()

            if not line:
                time.sleep(0.05)
                continue

            yield line


def to_seconds(t):
    h, m, s = map(int, t.split(":"))
    return h * 3600 + m * 60 + s


def severity_score(count):
    if count >= 10:
        return "HIGH"
    elif count >= 5:
        return "MEDIUM"
    else:
        return "LOW"

def parse_args():
    parser = argparse.ArgumentParser(description="Security Log Analyzer")

    parser.add_argument(
        "--realtime",
        action="store_true",
        help="Run in real-time monitoring mode"
    )

    parser.add_argument(
        "--batch",
        action="store_true",
        help="Run in batch analysis mode"
    )

    return parser.parse_args()


def alert(ip, user, count):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ALERT TRIGGERED")
    print(f"IP: {ip}")
    print(f"User: {user}")
    print(f"Attempts: {count}")

def main(mode):
    last_alert_time = {}

    ip_counts = {}
    user_counts = {}
    ip_times = defaultdict(list)
    sus_ip = {}

    alert_window = 60
    alert_threshold = 5

    event_counter = 0

    if mode == "realtime":
        log_stream = stream_file("auth.log")
    else:
        log_stream = open("auth.log", "r")

    print(f"=== STARTING {mode.upper()} SECURITY MONITOR ===\n")

    for line in log_stream:

        if "Failed password" not in line:
            continue

        match = re.search(pattern, line)
        if not match:
            continue

        time_str = match.group(1)
        user = match.group(2)
        ip = match.group(3)

        # store timestamps
        bisect.insort(ip_times[ip], to_seconds(time_str))

        # update counts safely
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        user_counts[user] = user_counts.get(user, 0) + 1

        event_counter += 1

        # LIVE SUMMARY (every 20 events)
        if event_counter % 20 == 0:
            print("\n=== LIVE TOP ATTACKERS ===")
            top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            for ip, count in top_ips:
                print(f"{ip}: {count} attempts")

        # BRUTE FORCE DETECTION 

        if ip_counts[ip] >= alert_threshold:

            start = 0
            times = ip_times[ip]

            for end in range(len(times)):
                while times[end] - times[start] > alert_window:
                    start += 1

                if (end - start + 1) >= alert_threshold:

                    # prevent spam alerts within same window
                    if ip not in last_alert_time or time.time() - last_alert_time[ip] > 60:

                        last_alert_time[ip] = time.time()
                        alert(ip, user, ip_counts[ip])
                        sus_ip[ip] = ip_counts[ip]

                    break

        # small sleep prevents CPU overuse
        time.sleep(0.05)

    # FINAL REPORT (only if loop ends manually) 
    print("\n=== FINAL SECURITY REPORT ===")

    for ip, count in ip_counts.items():
        severity = severity_score(count)
        print(f"{ip}: {count} attempts | SEVERITY: {severity}")

    print("\n=== TARGETED ACCOUNTS ===")
    for user, count in user_counts.items():
        print(f"{user}: {count} attempts")

    print("\n=== SUSPICIOUS IPS ===")
    for ip, count in sus_ip.items():
        print(f"{ip} ({count} FAILED ATTEMPTS)")

    # export report
    report = {
        "summary": {
            "total_ips": len(ip_counts),
            "total_users": len(user_counts),
            "total_events": sum(ip_counts.values())
        },
        "ip_counts": dict(ip_counts),
        "user_counts": dict(user_counts),
        "suspicious_ips": dict(sus_ip)
    }

    with open("security_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("\nReport saved to security_report.json")

    if hasattr(log_stream, "close"):
        log_stream.close()

if __name__ == "__main__":
    args = parse_args()

    if args.realtime:
        main("realtime")
    else:
        main("batch")