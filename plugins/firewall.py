import re

pattern = r"(\d+:\d+:\d+).*(\d+\.\d+\.\d+\.\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+)"

def parse(line):

    match = re.search(pattern, line)

    if not match:
        return None

    return {
        "time": match.group(1),
        "user": "N/A",
        "ip": match.group(2),
        "destination": match.group(3)
    }