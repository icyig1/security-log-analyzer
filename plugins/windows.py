"""Windows failed-logon (event 4625) parser.

A Windows event spans many lines, so unlike the other parsers this one reads
a whole stream and yields one result per event. It understands the text output of:

    wevtutil qe Security /q:"*[System[(EventID=4625)]]" /f:text > failed.txt

and the "Copy details as text" output from Event Viewer.
"""
import ipaddress
import re
from datetime import datetime

FAILED_LOGON = 4625

_EVENT_HEADER = re.compile(r"^Event\[\d+\]:")
_LOG_NAME = re.compile(r"^\s*Log Name:")
_EVENT_ID = re.compile(r"^\s*Event ID:\s*(\d+)")
_DATE = re.compile(r"^\s*Date:\s*(\S.*?)\s*$")
_FAILED_SECTION = re.compile(r"Account For Which Logon Failed", re.IGNORECASE)
_ACCOUNT_NAME = re.compile(r"Account Name:\s*(\S.*?)\s*$")
_SOURCE_ADDRESS = re.compile(r"Source Network Address:\s*(\S+)")
_ISO = re.compile(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})")
_LOCALE_FORMATS = ("%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S")


def _parse_date(text):
    match = _ISO.search(text)
    if match:
        return datetime.strptime(f"{match.group(1)} {match.group(2)}", "%Y-%m-%d %H:%M:%S")
    for fmt in _LOCALE_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            pass
    return None


def _parse_block(lines):
    event_id = when = ip = user = None
    in_failed_section = False

    for line in lines:
        match = _EVENT_ID.match(line)
        if match:
            event_id = int(match.group(1))
            continue

        match = _DATE.match(line)
        if match and when is None:
            when = _parse_date(match.group(1))
            continue

        if _FAILED_SECTION.search(line):
            in_failed_section = True
            continue

        # "Account Name" appears twice in a 4625 event: first for the *subject*
        # (the machine/process that reported it), then for the account that failed.
        match = _ACCOUNT_NAME.search(line)
        if match and in_failed_section and user is None:
            user = match.group(1)
            continue

        match = _SOURCE_ADDRESS.search(line)
        if match:
            ip = match.group(1)

    if event_id != FAILED_LOGON or when is None or ip is None:
        return None
    try:
        ipaddress.ip_address(ip)  # "-" (local logons) is rejected here
    except ValueError:
        return None

    return {"time": when, "user": user or "Unknown", "ip": ip}


def parse_events(lines):
    """Yield {"time", "user", "ip"} for each failed-logon event in `lines`."""
    block = []
    has_event_id = False

    for raw in lines:
        line = raw.rstrip("\r\n")
        starts_new_event = _EVENT_HEADER.match(line) or (_LOG_NAME.match(line) and has_event_id)
        if starts_new_event:
            event = _parse_block(block)
            if event:
                yield event
            block, has_event_id = [], False

        block.append(line)
        if _EVENT_ID.match(line):
            has_event_id = True

    event = _parse_block(block)
    if event:
        yield event
