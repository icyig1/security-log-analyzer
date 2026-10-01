import re
from datetime import datetime

# Common / combined log format:
# 203.0.113.9 - alice [10/Oct/2026:13:55:36 -0700] "POST /login HTTP/1.1" 401 512
PATTERN = re.compile(r'^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3})')
TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# Only authentication/authorization failures count as "attempts".
FAILED_STATUS = {"401", "403"}


def parse(line):
    match = PATTERN.match(line)
    if not match:
        return None

    ip, user, stamp, method, path, status = match.groups()
    if status not in FAILED_STATUS:
        return None

    try:
        when = datetime.strptime(stamp, TIME_FORMAT)
    except ValueError:
        return None

    return {
        "time": when,
        "user": "N/A" if user == "-" else user,
        "ip": ip,
        "method": method,
        "path": path,
        "status": int(status),
    }
