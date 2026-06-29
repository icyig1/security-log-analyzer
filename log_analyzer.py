import re
import json
import time
import argparse
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


def main():

    ip_counts = {}
    user_counts = {}
    ip_times = defaultdict(list)
    sus_ip = {}

    alert_window = 60
    alert_threshold = 5

    event_counter = 0

    print("=== STARTING REAL-TIME SECURITY MONITOR ===\n")

    for line in stream_file("auth.log"):

        if "Failed password" not in line:
            continue

        match = re.search(pattern, line)
        if not match:
            continue

        time_str = match.group(1)
        user = match.group(2)
        ip = match.group(3)

        # store timestamps
        ip_times[ip].append(time_str)

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
        seconds = sorted([to_seconds(t) for t in ip_times[ip]])

        start = 0
        detected = False

        for end in range(len(seconds)):
            while seconds[end] - seconds[start] > alert_window:
                start += 1

            if (end - start + 1) >= alert_threshold:
                if ip not in sus_ip:
                    print(f"\n🚨 BRUTE FORCE DETECTED FROM {ip}")
                    sus_ip[ip] = count
                detected = True
                break

        # small sleep prevents CPU overuse
        time.sleep(0.01)

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
        "ip_counts": dict(ip_counts),
        "user_counts": dict(user_counts),
        "suspicious_ips": dict(sus_ip)
    }

    with open("security_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("\nReport saved to security_report.json")


if __name__ == "__main__":
    main()