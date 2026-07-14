import re

pattern = r"^\w+\s+\d+\s+(\d+:\d+:\d+).*Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)"

def parse(line):
    match = re.search(pattern, line)

    if not match:
        return None

    return {
        "time": match.group(1),
        "user": match.group(2),
        "ip": match.group(3)
    }