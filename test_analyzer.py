import json
from datetime import datetime, timedelta

import apache
import firewall
import linux
import windows
from log_analyzer import Detector, run


# ------------------------------------------------------------------- linux


def test_linux_failed_password():
    event = linux.parse("Jul 13 12:00:01 host sshd[1]: Failed password for admin from 192.168.1.50 port 22 ssh2")
    assert event["user"] == "admin"
    assert event["ip"] == "192.168.1.50"
    assert (event["time"].month, event["time"].day, event["time"].hour) == (7, 13, 12)


def test_linux_invalid_user_is_not_dropped():
    event = linux.parse("Jul 13 12:00:01 host sshd[1]: Failed password for invalid user bob from 1.2.3.4 port 22 ssh2")
    assert event["user"] == "bob"
    assert event["ip"] == "1.2.3.4"


def test_linux_ignores_successful_login():
    assert linux.parse("Jul 13 12:00:01 host sshd[1]: Accepted password for user from 10.0.0.15 port 22") is None


def test_linux_iso_timestamp_and_ipv6():
    event = linux.parse("2026-07-13T12:00:01.123456+00:00 host sshd[1]: Failed password for root from 2001:db8::1 port 22")
    assert event["time"] == datetime(2026, 7, 13, 12, 0, 1)
    assert event["ip"] == "2001:db8::1"


# ---------------------------------------------------------------- firewall


def test_firewall_keeps_full_source_ip():
    event = firewall.parse("Jul 13 12:00:01 fw DROP 192.168.1.50 -> 10.0.0.1")
    assert event["ip"] == "192.168.1.50"
    assert event["destination"] == "10.0.0.1"
    assert firewall.parse("Jul 13 12:00:01 fw DROP 10.0.0.5 -> 8.8.8.8")["ip"] == "10.0.0.5"


def test_firewall_ignores_allowed_traffic():
    assert firewall.parse("Jul 13 12:00:01 fw ALLOW 10.0.0.5 -> 8.8.8.8") is None


def test_firewall_iptables_format():
    event = firewall.parse("Jul 13 12:00:01 fw kernel: DROP IN=eth0 SRC=203.0.113.7 DST=10.0.0.1 PROTO=TCP DPT=22")
    assert event["ip"] == "203.0.113.7"


# ------------------------------------------------------------------ apache

APACHE_401 = '203.0.113.9 - alice [10/Oct/2026:13:55:36 -0700] "POST /login HTTP/1.1" 401 512'
APACHE_200 = '203.0.113.9 - - [10/Oct/2026:13:55:40 -0700] "GET /index.html HTTP/1.1" 200 2326'


def test_apache_401_becomes_an_event_with_a_datetime():
    event = apache.parse(APACHE_401)
    assert event["ip"] == "203.0.113.9"
    assert event["user"] == "alice"
    assert event["status"] == 401
    assert isinstance(event["time"], datetime)


def test_apache_ignores_successful_requests():
    assert apache.parse(APACHE_200) is None


# ----------------------------------------------------------------- windows

WEVTUTIL_EVENTS = "\n".join(
    [
        "Event[0]:",
        "  Log Name: Security",
        "  Date: 2026-07-13T12:00:01.123",
        "  Event ID: 4625",
        "  Description:",
        "An account failed to log on.",
        "",
        "Subject:",
        "\tSecurity ID:\t\tSYSTEM",
        "\tAccount Name:\t\tWIN-SRV$",
        "",
        "Account For Which Logon Failed:",
        "\tSecurity ID:\t\tNULL SID",
        "\tAccount Name:\t\tadmin",
        "",
        "Network Information:",
        "\tSource Network Address:\t203.0.113.7",
        "",
        "Event[1]:",
        "  Log Name: Security",
        "  Date: 2026-07-13T12:00:09.000",
        "  Event ID: 4624",
        "\tAccount Name:\t\talice",
        "\tSource Network Address:\t198.51.100.4",
        "",
        "Event[2]:",
        "  Log Name: Security",
        "  Date: 2026-07-13T12:00:12.000",
        "  Event ID: 4625",
        "Account For Which Logon Failed:",
        "\tAccount Name:\t\troot",
        "\tSource Network Address:\t-",
    ]
)


def test_windows_reads_failed_account_not_subject_and_skips_other_events():
    events = list(windows.parse_events(WEVTUTIL_EVENTS.splitlines()))
    assert len(events) == 1  # 4624 (success) and the local "-" logon are skipped
    assert events[0]["user"] == "admin"
    assert events[0]["ip"] == "203.0.113.7"
    assert events[0]["time"] == datetime(2026, 7, 13, 12, 0, 1)


def test_windows_event_viewer_copy_format_with_am_pm():
    text = "\n".join(
        [
            "Log Name:      Security",
            "Date:          7/13/2026 1:05:09 PM",
            "Event ID:      4625",
            "Account For Which Logon Failed:",
            "\tAccount Name:\t\tadmin",
            "\tSource Network Address:\t203.0.113.7",
            "",
            "Log Name:      Security",
            "Date:          7/13/2026 1:05:12 PM",
            "Event ID:      4625",
            "Account For Which Logon Failed:",
            "\tAccount Name:\t\tadmin",
            "\tSource Network Address:\t203.0.113.7",
        ]
    )
    events = list(windows.parse_events(text.splitlines()))
    assert [e["time"].hour for e in events] == [13, 13]
    assert len(events) == 2


# ---------------------------------------------------------------- detector


def event(ip, when, user="root"):
    return {"ip": ip, "user": user, "time": when}


def run_events(detector, events):
    return [a for a in (detector.process(e) for e in events) if a]


START = datetime(2026, 7, 13, 12, 0, 0)


def test_fast_burst_alerts():
    detector = Detector()
    alerts = run_events(detector, [event("1.1.1.1", START + timedelta(seconds=5 * i)) for i in range(5)])
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "MEDIUM"


def test_slow_attempts_do_not_alert():
    detector = Detector()
    alerts = run_events(detector, [event("1.1.1.1", START + timedelta(seconds=63 * i)) for i in range(6)])
    assert alerts == []
    assert detector.ip_counts["1.1.1.1"] == 6


def test_window_works_across_midnight():
    detector = Detector()
    base = datetime(2026, 7, 13, 23, 59, 50)
    alerts = run_events(detector, [event("1.1.1.1", base + timedelta(seconds=5 * i)) for i in range(5)])
    assert len(alerts) == 1


def test_second_burst_later_in_the_log_alerts_again():
    detector = Detector()
    first = [event("1.1.1.1", START + timedelta(seconds=5 * i)) for i in range(5)]
    second = [event("1.1.1.1", START + timedelta(minutes=10, seconds=5 * i)) for i in range(5)]
    assert len(run_events(detector, first + second)) == 2


def test_severity_uses_peak_inside_the_window():
    detector = Detector()
    run_events(detector, [event("1.1.1.1", START + timedelta(seconds=i)) for i in range(10)])
    assert detector.suspicious["1.1.1.1"]["severity"] == "HIGH"
    assert detector.suspicious["1.1.1.1"]["peak_window_attempts"] == 10


# --------------------------------------------------------------- end to end


def test_batch_run_writes_report(tmp_path, capsys):
    log = tmp_path / "auth.log"
    lines = [f"Jul 13 12:00:{5 * i:02d} host sshd[1]: Failed password for admin from 192.168.1.50 port 22 ssh2" for i in range(5)]
    lines.append("Jul 13 12:01:00 host sshd[1]: Accepted password for user from 10.0.0.15 port 22")
    log.write_text("\n".join(lines))
    output = tmp_path / "report.json"

    assert run("batch", str(log), "linux", output=output) == 0

    report = json.loads(output.read_text())
    assert report["summary"]["total_events"] == 5
    assert report["suspicious_ips"]["192.168.1.50"]["severity"] == "MEDIUM"
    assert "ALERT" in capsys.readouterr().out
