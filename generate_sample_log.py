"""
Generates a synthetic SSH authentication log (data/sample_auth.log) in standard
Linux syslog format, mixing normal login activity with a simulated brute-force
attack and a few off-hours logins. Used only to have realistic sample data to
run detect.py against -- this is NOT real server data.
"""
import random
from datetime import datetime, timedelta

random.seed(42)

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

HOST = "prod-web01"
NORMAL_USERS = ["vcarotenuto", "admin", "deploy", "backup"]
NORMAL_IPS = ["192.168.1.10", "192.168.1.14", "10.0.0.5", "10.0.0.8"]
ATTACKER_IP = "185.220.101.47"
ATTACKER_USERS = ["root", "admin", "test", "oracle", "postgres", "ubuntu",
                   "root", "admin", "root", "user", "guest", "root"]

lines = []
pid_counter = 10000


def fmt(dt, msg):
    ts = f"{MONTHS[dt.month-1]} {dt.day:2d} {dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
    return f"{ts} {HOST} sshd[{pid_counter}]: {msg}"


start = datetime(2026, 7, 20, 0, 0, 0)

# --- Normal daytime logins across a week ---
for day in range(7):
    day_start = start + timedelta(days=day)
    for _ in range(random.randint(3, 6)):
        hour = random.randint(8, 19)  # working hours
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        ts = day_start.replace(hour=hour, minute=minute, second=second)
        user = random.choice(NORMAL_USERS)
        ip = random.choice(NORMAL_IPS)
        pid_counter += 1
        if random.random() < 0.08:
            lines.append((ts, fmt(ts, f"Failed password for {user} from {ip} port {random.randint(30000,60000)} ssh2")))
            ts2 = ts + timedelta(seconds=random.randint(3, 20))
            pid_counter += 1
            lines.append((ts2, fmt(ts2, f"Accepted password for {user} from {ip} port {random.randint(30000,60000)} ssh2")))
        else:
            lines.append((ts, fmt(ts, f"Accepted password for {user} from {ip} port {random.randint(30000,60000)} ssh2")))

# --- A couple of genuine off-hours logins (legit but worth flagging) ---
for day in [2, 5]:
    ts = (start + timedelta(days=day)).replace(hour=3, minute=random.randint(0, 59))
    pid_counter += 1
    lines.append((ts, fmt(ts, f"Accepted password for backup from 10.0.0.8 port {random.randint(30000,60000)} ssh2")))

# --- Simulated brute-force attack on day 4, concentrated in ~2 minutes ---
attack_start = start + timedelta(days=4, hours=2, minutes=14)
t = attack_start
for user in ATTACKER_USERS * 4:  # 48 rapid attempts
    t += timedelta(seconds=random.randint(1, 4))
    pid_counter += 1
    lines.append((t, fmt(t, f"Failed password for {user} from {ATTACKER_IP} port {random.randint(30000,60000)} ssh2")))

# One more isolated failed attempt from a normal IP (just noise, not an attack)
ts = start + timedelta(days=3, hours=14, minutes=22)
pid_counter += 1
lines.append((ts, fmt(ts, f"Failed password for admin from 192.168.1.14 port 41210 ssh2")))

# Sort all lines chronologically and write out
lines.sort(key=lambda x: x[0])

with open("data/sample_auth.log", "w") as f:
    for _, line in lines:
        f.write(line + "\n")

print(f"Generated {len(lines)} log lines -> data/sample_auth.log")
