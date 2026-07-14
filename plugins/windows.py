import re

time_pattern = r"(\d+:\d+:\d+)"
user_pattern = r"Account Name:\s+(\S+)"
ip_pattern = r"Source Network Address:\s+(\d+\.\d+\.\d+\.\d+)"

def parse(line):

    ip = re.search(ip_pattern, line)
    user = re.search(user_pattern, line)
    time = re.search(time_pattern, line)

    if not ip:
        return None

    return {
        "time": time.group(1) if time else "Unknown",
        "user": user.group(1) if user else "Unknown",
        "ip": ip.group(1)
    }