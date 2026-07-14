import re

pattern = r"(\d+\.\d+\.\d+\.\d+).*\[(.*?)\].*\"(GET|POST).*\" (\d+)"

def parse(line):

    match = re.search(pattern, line)

    if not match:
        return None

    return {
        "time": match.group(2),
        "user": "N/A",
        "ip": match.group(1),
        "method": match.group(3),
        "status": match.group(4)
    }