"""Security log analyzer.

Flags an IP when it produces `threshold` or more failure events inside a
sliding `window`. Supported inputs:

    linux     sshd "Failed password" / "Failed publickey" lines (auth.log)
    apache    access-log lines with HTTP 401/403
    windows   failed-logon events (4625) exported as text with wevtutil
    firewall  DROP/DENY/BLOCK/REJECT lines ("a -> b" or SRC=/DST= style)

Usage:
    python log_analyzer.py auth.log --type linux
    python log_analyzer.py auth.log --type linux --realtime
    python log_analyzer.py capture.pcap
"""
import argparse
import json
import os
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

import apache
import firewall
import linux
import windows

REPORT_PATH = Path(__file__).with_name("security_report.json")
ALERT_WINDOW = timedelta(seconds=60)
ALERT_THRESHOLD = 5
REPORT_INTERVAL = 2.0  # seconds between report writes in realtime mode

LINE_PARSERS = {
    "linux": linux.parse,
    "apache": apache.parse,
    "firewall": firewall.parse,
}


# ----------------------------------------------------------------- detection


def severity_score(count):
    if count >= 10:
        return "HIGH"
    elif count >= 5:
        return "MEDIUM"
    return "LOW"


class Detector:
    """Sliding-window brute-force detector.

    All timing uses the timestamps found in the log, not the wall clock, so a
    log replayed in batch mode behaves the same as one watched live.
    """

    def __init__(self, window=ALERT_WINDOW, threshold=ALERT_THRESHOLD):
        self.window = window
        self.threshold = threshold
        self.events = 0
        self.ip_counts = Counter()
        self.user_counts = Counter()
        self.suspicious = {}
        self._recent = defaultdict(deque)  # ip -> timestamps inside the window
        self._last_alert = {}  # ip -> log time of the last alert

    def process(self, event):
        """Record one failure event. Returns an alert dict when one fires."""
        ip, user, when = event["ip"], event["user"], event["time"]

        recent = self._recent[ip]
        recent.append(when)
        while when - recent[0] > self.window:
            recent.popleft()

        self.events += 1
        self.ip_counts[ip] += 1
        if user not in (None, "N/A"):
            self.user_counts[user] += 1

        in_window = len(recent)
        if in_window < self.threshold:
            return None

        severity = severity_score(in_window)
        entry = self.suspicious.setdefault(
            ip,
            {
                "severity": severity,
                "peak_window_attempts": in_window,
                "first_alert": when.isoformat(),
                "last_alert": when.isoformat(),
            },
        )
        if in_window > entry["peak_window_attempts"]:
            entry["peak_window_attempts"] = in_window
            entry["severity"] = severity

        last = self._last_alert.get(ip)
        if last is not None and when - last <= self.window:
            return None  # still inside the cooldown for this burst

        self._last_alert[ip] = when
        entry["last_alert"] = when.isoformat()
        return {
            "time": when,
            "ip": ip,
            "user": user,
            "window_attempts": in_window,
            "total_attempts": self.ip_counts[ip],
            "severity": severity,
        }

    def build_report(self):
        return {
            "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "rule": {
                "window_seconds": int(self.window.total_seconds()),
                "threshold": self.threshold,
            },
            "summary": {
                "total_ips": len(self.ip_counts),
                "total_users": len(self.user_counts),
                "total_events": self.events,
                "suspicious_ips": len(self.suspicious),
            },
            "ip_counts": dict(self.ip_counts),
            "user_counts": dict(self.user_counts),
            "suspicious_ips": {
                ip: {"attempts": self.ip_counts[ip], **data}
                for ip, data in self.suspicious.items()
            },
        }


# ------------------------------------------------------------------- input


def open_log(path):
    """Open a text log, handling the UTF-16 files PowerShell redirection creates."""
    with open(path, "rb") as f:
        head = f.read(2)
    encoding = "utf-16" if head in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
    return open(path, "r", encoding=encoding, errors="replace")


def stream_file(path):
    """Yield new lines as they are appended (like `tail -f`)."""
    with open_log(path) as file:
        file.seek(0, 2)  # start at the end of the file
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.05)
                continue
            yield line


def iter_events(lines, log_type):
    if log_type == "windows":
        yield from windows.parse_events(lines)
        return

    parse = LINE_PARSERS[log_type]
    for line in lines:
        event = parse(line)
        if event is not None:
            yield event


# ------------------------------------------------------------ network (basic)


def analyze_pcap(filename):
    from scapy.all import rdpcap  # imported here so log analysis needs no scapy

    for packet in rdpcap(filename):
        print(packet.summary())


def live_capture():
    from scapy.all import sniff  # needs admin/root

    sniff(store=False, prn=lambda pkt: print(pkt.summary()))


# ------------------------------------------------------------------ output


def print_alert(alert):
    print(f"[{alert['time']}] ALERT")
    print(f"Severity: {alert['severity']}")
    print(f"IP: {alert['ip']}")
    print(f"User: {alert['user']}")
    print(f"Attempts in window: {alert['window_attempts']} (total: {alert['total_attempts']})")


def print_top_attackers(detector):
    print("\n=== LIVE TOP ATTACKERS ===")
    for ip, count in detector.ip_counts.most_common(5):
        print(f"{ip}: {count} attempts")


def print_summary(detector):
    print("\n=== FINAL SECURITY REPORT ===")
    for ip, count in detector.ip_counts.most_common():
        print(f"{ip}: {count} attempts")

    print("\n=== TARGETED ACCOUNTS ===")
    for user, count in detector.user_counts.most_common():
        print(f"{user}: {count} attempts")

    print("\n=== SUSPICIOUS IPS ===")
    for ip, data in detector.suspicious.items():
        print(
            f"{ip} ({detector.ip_counts[ip]} total, peak {data['peak_window_attempts']} "
            f"in window) - SEVERITY: {data['severity']}"
        )


def write_report(detector, path):
    """Write the report atomically so the dashboard never reads a half-written file."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(detector.build_report(), f, indent=4)
    try:
        os.replace(tmp, path)
    except PermissionError:  # Windows: dashboard has the file open this instant
        return False
    return True


# -------------------------------------------------------------------- main


def run(mode, logfile, log_type, window=ALERT_WINDOW, threshold=ALERT_THRESHOLD, output=REPORT_PATH):
    if str(logfile).lower().endswith((".pcap", ".pcapng")):
        analyze_pcap(logfile)
        return 0

    if not Path(logfile).is_file():
        print(f"ERROR: {logfile} not found")
        return 1

    detector = Detector(window, threshold)
    lines = stream_file(logfile) if mode == "realtime" else open_log(logfile)

    print(f"=== STARTING {mode.upper()} SECURITY MONITOR ===\n")
    last_write = 0.0
    try:
        for event in iter_events(lines, log_type):
            alert = detector.process(event)
            if alert:
                print_alert(alert)

            if detector.events % 20 == 0:
                print_top_attackers(detector)

            if mode == "realtime" and time.monotonic() - last_write >= REPORT_INTERVAL:
                write_report(detector, output)
                last_write = time.monotonic()
    except KeyboardInterrupt:
        print("\nStopping monitor...")
    finally:
        lines.close()

    print_summary(detector)
    if write_report(detector, output):
        print(f"\nReport saved to {output}")
    else:
        print(f"\nWARNING: could not write {output} (file in use?)")
    return 0


def parse_args():
    parser = argparse.ArgumentParser(description="Security Log Analyzer")

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--realtime", action="store_true", help="watch the file for new lines")
    mode.add_argument("--batch", action="store_true", help="analyze the whole file and exit (default)")
    mode.add_argument("--network", action="store_true", help="print a live packet summary (needs scapy and admin/root)")

    parser.add_argument("logfile", nargs="?", help="path to the log file (or .pcap)")
    parser.add_argument("--type", default="linux", choices=["linux", "apache", "windows", "firewall"], help="type of log file")
    parser.add_argument("--window", type=int, default=int(ALERT_WINDOW.total_seconds()), help="sliding window in seconds")
    parser.add_argument("--threshold", type=int, default=ALERT_THRESHOLD, help="failures inside the window that trigger an alert")
    parser.add_argument("--output", default=str(REPORT_PATH), help="where to write the JSON report")

    args = parser.parse_args()
    if not args.network and not args.logfile:
        parser.error("logfile is required unless --network is used")
    return args


def main():
    args = parse_args()

    if args.network:
        live_capture()
        return 0

    mode = "realtime" if args.realtime else "batch"
    return run(mode, args.logfile, args.type, timedelta(seconds=args.window), args.threshold, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
