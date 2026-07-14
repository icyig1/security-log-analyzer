import re
import json
import time
import argparse

import linux
import apache
import windows
import firewall

from collections import defaultdict, deque

from scapy.all import rdpcap
from scapy.all import sniff

try:
    import win32evtlog
except ImportError:
    win32evtlog = None

import socket

# Match: time, user, ip


def receive_logs():

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.bind(("0.0.0.0", 514))

    while True:

        data, addr = sock.recvfrom(4096)

        print(data.decode())

def watch_folder(folder):
    print("Watching", folder)

def read_windows_logs():

    if win32evtlog is None:
        print("Windows Event Logs are only supported on Windows.")
        return

    server = "localhost"

    logtype = "Security"

    hand = win32evtlog.OpenEventLog(server, logtype)

    events = win32evtlog.ReadEventLog(
        hand,
        win32evtlog.EVENTLOG_FORWARDS_READ,
        0
    )

    for event in events:
        print(event.EventID)

def analyze_pcap(filename):

    packets = rdpcap(filename)

    for packet in packets:
        print(packet.summary())

def live_capture():
    sniff(store=False, prn=lambda pkt: print(pkt.summary()))

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
        "--network",
        action="store_true"
    )

    parser.add_argument(
        "--batch",
        action="store_true",
        help="Run in batch analysis mode"
    )
    
    parser.add_argument(
        "logfile",
        help="Path to the log file"
    )
    parser.add_argument(
        "--type",
        default="linux",
        choices=["linux", "apache", "windows", "firewall"],
        help="Type of log file"
    )

    return parser.parse_args()


def alert(ip, user, count, severity):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ALERT")
    print(f"Severity: {severity}")
    print(f"IP: {ip}")
    print(f"User: {user}")
    print(f"Attempts: {count}")

def main(mode, logfile, log_type):
    last_alert_time = {}

    ip_counts = {}
    user_counts = {}
    ip_times = defaultdict(deque)
    sus_ip = {}

    alert_window = 60
    alert_threshold = 5

    event_counter = 0
    

    try:
        if logfile.endswith(".pcap"):
            analyze_pcap(logfile)
            return

        if mode == "realtime":
            log_stream = stream_file(logfile)
        else:
            log_stream = open(logfile, "r")
    except FileNotFoundError:
        print(f"ERROR: {logfile} not found")
        return

    print(f"=== STARTING {mode.upper()} SECURITY MONITOR ===\n")
    try:
        for line in log_stream:

            if log_type == "linux" and "Failed password" not in line:
                continue

            if log_type == "linux":
                result = linux.parse(line)

            elif log_type == "apache":
                result = apache.parse(line)

            elif log_type == "windows":
                result = windows.parse(line)

            elif log_type == "firewall":
                result = firewall.parse(line)

            else:
                continue

            if result is None:
                continue

            time_str = result["time"]
            user = result["user"]
            ip = result["ip"]

            

            # Convert timestamp to seconds
            current_time = to_seconds(time_str)

            # Add newest timestamp
            ip_times[ip].append(current_time)

            # Remove timestamps outside the alert window
            while ip_times[ip] and current_time - ip_times[ip][0] > alert_window:
                ip_times[ip].popleft()

            # Update counters
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            user_counts[user] = user_counts.get(user, 0) + 1

            event_counter += 1

            # Live summary every 20 failed logins
            if event_counter % 20 == 0:
                print("\n=== LIVE TOP ATTACKERS ===")
                top_ips = sorted(
                    ip_counts.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:5]

                for top_ip, count in top_ips:
                    print(f"{top_ip}: {count} attempts")

            if len(ip_times[ip]) >= alert_threshold:

                if ip not in last_alert_time or time.time() - last_alert_time[ip] > alert_window:

                    last_alert_time[ip] = time.time()

                    severity = severity_score(ip_counts[ip])
                    alert(ip, user, ip_counts[ip], severity)

                    sus_ip[ip] = {
                        "attempts": ip_counts[ip],
                        "severity": severity
                    }
            if mode == "realtime":
                time.sleep(0.05)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
          

    # FINAL REPORT (only if loop ends manually) 
    print("\n=== FINAL SECURITY REPORT ===")

    for ip, count in sorted(ip_counts.items(),
                        key=lambda x: x[1],
                        reverse=True):
        severity = severity_score(count)
        print(f"{ip}: {count} attempts | SEVERITY: {severity}")

    print("\n=== TARGETED ACCOUNTS ===")
    for user, count in user_counts.items():
        print(f"{user}: {count} attempts")

    print("\n=== SUSPICIOUS IPS ===")
    for ip, data in sus_ip.items():
        print(f"{ip} ({data['attempts']} FAILED ATTEMPTS) - SEVERITY: {data['severity']}")

    # export report
    report = {
        "summary": {
            "total_ips": len(ip_counts),
            "total_users": len(user_counts),
            "total_events": sum(ip_counts.values())
        },
        "ip_counts": dict(ip_counts),
        "user_counts": dict(user_counts),
        "suspicious_ips": sus_ip
    }

    with open("security_report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("\nReport saved to security_report.json")

    if hasattr(log_stream, "close"):
        log_stream.close()

if __name__ == "__main__":

    args = parse_args()

    if args.network:
        live_capture()

    elif args.realtime:
        main("realtime", args.logfile, args.type)

    else:
        main("batch", args.logfile, args.type)