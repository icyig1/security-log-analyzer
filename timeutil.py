"""Shared timestamp parsing for log lines.

Every parser returns a real datetime so the analyzer can do window math
across midnight, month ends and multi-day logs.
"""
import re
from datetime import datetime, timedelta

_ISO = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})")
_SYSLOG = re.compile(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})")
_TIME_ONLY = re.compile(r"(\d{1,2}:\d{2}:\d{2})")


def parse_timestamp(line, now=None):
    """Return a datetime for the timestamp at the start of `line`, or None.

    Understands ISO timestamps (2026-07-13T12:00:01), classic syslog
    timestamps (Jul 13 12:00:01, no year), and, as a last resort, a bare
    HH:MM:SS anywhere in the line (assumed to be today).
    """
    now = now or datetime.now()

    m = _ISO.match(line)
    if m:
        try:
            return datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None

    m = _SYSLOG.match(line)
    if m:
        try:
            ts = datetime.strptime(
                f"{now.year} {m.group(1)} {m.group(2)} {m.group(3)}", "%Y %b %d %H:%M:%S"
            )
        except ValueError:
            return None
        # Syslog has no year: a "Dec 31" line read in January belongs to last year.
        if ts - now > timedelta(days=1):
            ts = ts.replace(year=now.year - 1)
        return ts

    m = _TIME_ONLY.search(line)
    if m:
        try:
            clock = datetime.strptime(m.group(1), "%H:%M:%S").time()
        except ValueError:
            return None
        return datetime.combine(now.date(), clock)

    return None
