import ipaddress
import re

from timeutil import parse_timestamp

# Handles both "Failed password for root from ..." and
# "Failed password for invalid user bob from ..." (nonexistent accounts).
FAILED = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)")


def parse(line):
    match = FAILED.search(line)
    if not match:
        return None

    user, ip = match.groups()
    try:
        ipaddress.ip_address(ip)  # accepts IPv4 and IPv6, rejects garbage
    except ValueError:
        return None

    when = parse_timestamp(line)
    if when is None:
        return None

    return {"time": when, "user": user, "ip": ip}
