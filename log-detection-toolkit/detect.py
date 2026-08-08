"""
detect.py - Log Detection Toolkit

Parses an SSH authentication log (standard Linux syslog format) and flags
suspicious activity:
  1. Brute-force attempts: an IP with too many failed logins in a short time window
  2. Off-hours logins: successful logins outside normal working hours
  3. Successful login following a burst of failures (possible compromise)

Usage:
    python3 detect.py data/sample_auth.log
    python3 detect.py data/sample_auth.log --fail-threshold 10 --window-minutes 5

Output:
    Prints a summary to the terminal and writes output/alerts.csv
"""
import argparse
import csv
import re
from collections import defaultdict
from datetime import datetime

LOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<status>Failed|Accepted)\s+password\s+for\s+(?P<user>\S+)\s+"
    r"from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)"
)

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}

WORK_START_HOUR = 7   # before this hour = off-hours
WORK_END_HOUR = 21    # after this hour = off-hours
YEAR_ASSUMED = 2026    # log lines have no year; assumed for parsing only


def parse_log(path):
    events = []
    with open(path) as f:
        for line_num, line in enumerate(f, 1):
            m = LOG_PATTERN.match(line.strip())
            if not m:
                continue
            d = m.groupdict()
            dt = datetime(
                YEAR_ASSUMED, MONTHS[d["month"]], int(d["day"]),
                *map(int, d["time"].split(":"))
            )
            events.append({
                "line": line_num,
                "datetime": dt,
                "status": d["status"],
                "user": d["user"],
                "ip": d["ip"],
            })
    return sorted(events, key=lambda e: e["datetime"])


def detect_bruteforce(events, fail_threshold, window_minutes):
    """Flag IPs with >= fail_threshold failed attempts within window_minutes."""
    alerts = []
    by_ip = defaultdict(list)
    for e in events:
        if e["status"] == "Failed":
            by_ip[e["ip"]].append(e["datetime"])

    for ip, timestamps in by_ip.items():
        timestamps.sort()
        window = []
        for ts in timestamps:
            window.append(ts)
            window = [t for t in window if (ts - t).total_seconds() <= window_minutes * 60]
            if len(window) >= fail_threshold:
                alerts.append({
                    "type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "ip": ip,
                    "detail": f"{len(window)} failed logins within {window_minutes} min "
                              f"(window ending {ts.strftime('%b %d %H:%M:%S')})",
                })
                break  # one alert per IP is enough for this simple version
    return alerts


def detect_offhours(events):
    """Flag successful logins outside normal working hours."""
    alerts = []
    for e in events:
        if e["status"] == "Accepted" and not (WORK_START_HOUR <= e["datetime"].hour < WORK_END_HOUR):
            alerts.append({
                "type": "OFF_HOURS_LOGIN",
                "severity": "MEDIUM",
                "ip": e["ip"],
                "detail": f"Successful login for '{e['user']}' at "
                          f"{e['datetime'].strftime('%b %d %H:%M:%S')} (outside {WORK_START_HOUR}:00-{WORK_END_HOUR}:00)",
            })
    return alerts


def detect_success_after_failures(events, fail_threshold=3, window_minutes=5):
    """Flag a successful login for an IP that had several recent failures (possible breach)."""
    alerts = []
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)

    for ip, ip_events in by_ip.items():
        for i, e in enumerate(ip_events):
            if e["status"] != "Accepted":
                continue
            recent_fails = [
                x for x in ip_events[:i]
                if x["status"] == "Failed"
                and (e["datetime"] - x["datetime"]).total_seconds() <= window_minutes * 60
            ]
            if len(recent_fails) >= fail_threshold:
                alerts.append({
                    "type": "SUCCESS_AFTER_FAILURES",
                    "severity": "HIGH",
                    "ip": ip,
                    "detail": f"Successful login for '{e['user']}' after {len(recent_fails)} "
                              f"failed attempts within {window_minutes} min "
                              f"({e['datetime'].strftime('%b %d %H:%M:%S')})",
                })
    return alerts


def main():
    parser = argparse.ArgumentParser(description="Detect suspicious patterns in SSH auth logs.")
    parser.add_argument("logfile", help="Path to the auth log file")
    parser.add_argument("--fail-threshold", type=int, default=10,
                         help="Failed attempts within window to flag brute-force (default: 10)")
    parser.add_argument("--window-minutes", type=int, default=5,
                         help="Time window in minutes for brute-force detection (default: 5)")
    parser.add_argument("--output", default="output/alerts.csv", help="Path to write CSV alerts")
    args = parser.parse_args()

    events = parse_log(args.logfile)
    print(f"Parsed {len(events)} authentication events from {args.logfile}\n")

    alerts = []
    alerts += detect_bruteforce(events, args.fail_threshold, args.window_minutes)
    alerts += detect_offhours(events)
    alerts += detect_success_after_failures(events)

    # Sort: HIGH severity first
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    alerts.sort(key=lambda a: severity_order.get(a["severity"], 3))

    if not alerts:
        print("No suspicious activity detected.")
    else:
        print(f"{len(alerts)} alert(s) found:\n")
        for a in alerts:
            print(f"  [{a['severity']:6}] {a['type']:24} ip={a['ip']:16} {a['detail']}")

    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["type", "severity", "ip", "detail"])
        writer.writeheader()
        writer.writerows(alerts)
    print(f"\nFull report written to {args.output}")


if __name__ == "__main__":
    main()
