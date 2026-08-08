"""
load_log_to_sqlite.py

Parses the SSH auth log (same format as detect.py) and loads it into a local
SQLite database (output/auth_events.db), then runs detection_queries.sql
against it and prints the results. This makes the SQL detection approach
actually runnable, not just illustrative.

Usage:
    python3 sql/load_log_to_sqlite.py data/sample_auth.log
"""
import argparse
import re
import sqlite3
from datetime import datetime
from pathlib import Path

LOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<status>Failed|Accepted)\s+password\s+for\s+(?P<user>\S+)\s+"
    r"from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)"
)
MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}
YEAR_ASSUMED = 2026


def load_events(path):
    rows = []
    with open(path) as f:
        for line in f:
            m = LOG_PATTERN.match(line.strip())
            if not m:
                continue
            d = m.groupdict()
            dt = datetime(YEAR_ASSUMED, MONTHS[d["month"]], int(d["day"]),
                           *map(int, d["time"].split(":")))
            rows.append((dt.strftime("%Y-%m-%d %H:%M:%S"), d["status"], d["user"], d["ip"]))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile")
    parser.add_argument("--db", default="output/auth_events.db")
    args = parser.parse_args()

    Path("output").mkdir(exist_ok=True)
    rows = load_events(args.logfile)

    conn = sqlite3.connect(args.db)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS auth_events")
    cur.execute("""
        CREATE TABLE auth_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT,
            status TEXT,
            user TEXT,
            ip TEXT
        )
    """)
    cur.executemany(
        "INSERT INTO auth_events (event_time, status, user, ip) VALUES (?, ?, ?, ?)",
        rows
    )
    conn.commit()
    print(f"Loaded {len(rows)} events into {args.db}\n")

    sql_script = Path(__file__).parent / "detection_queries.sql"
    queries = sql_script.read_text().split(";")

    titles = [
        "Brute-force detection (>=10 failed logins in a 5-min bucket)",
        "Off-hours successful logins (outside 07:00-21:00)",
        "Successful login after multiple recent failures",
        "Summary: failed vs successful logins per IP",
    ]
    i = 0
    for q in queries:
        q = q.strip()
        if not q or q.startswith("--") and "SELECT" not in q.upper():
            continue
        # skip pure comment blocks
        clean = "\n".join(l for l in q.splitlines() if not l.strip().startswith("--"))
        if not clean.strip():
            continue
        print(f"--- {titles[i] if i < len(titles) else f'Query {i+1}'} ---")
        try:
            cur.execute(clean)
            results = cur.fetchall()
            cols = [desc[0] for desc in cur.description]
            print(" | ".join(cols))
            for r in results:
                print(" | ".join(str(x) for x in r))
            if not results:
                print("(no rows)")
        except sqlite3.Error as e:
            print(f"Query error: {e}")
        print()
        i += 1

    conn.close()


if __name__ == "__main__":
    main()
