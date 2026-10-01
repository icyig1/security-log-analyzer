import re

from timeutil import parse_timestamp

_IP = r"\d{1,3}(?:\.\d{1,3}){3}"

# "192.168.1.50 -> 10.0.0.1" (optionally with :ports). The lookbehind stops the
# match from starting in the middle of an address.
ARROW = re.compile(rf"(?<![\d.])({_IP})(?::\d+)?\s*->\s*({_IP})")
# iptables / UFW style: "SRC=192.168.1.50 DST=10.0.0.1"
KEY_VALUE = re.compile(rf"\bSRC=({_IP})\b.*?\bDST=({_IP})\b")
# Only blocked traffic counts; ALLOW lines are ignored.
BLOCKED = re.compile(r"\b(?:DROP|DENY|BLOCK|REJECT)", re.IGNORECASE)


def parse(line):
    if not BLOCKED.search(line):
        return None

    match = ARROW.search(line) or KEY_VALUE.search(line)
    if not match:
        return None
    source, destination = match.groups()

    when = parse_timestamp(line)
    if when is None:
        return None

    return {"time": when, "user": "N/A", "ip": source, "destination": destination}
