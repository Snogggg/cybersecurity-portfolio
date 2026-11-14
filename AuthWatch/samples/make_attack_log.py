"""Generate samples/attack-auth.log: a SYNTHETIC log with four scenarios.
IPs come from the documentation ranges (RFC 5737), so they are not real hosts."""

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(13)
TZ = timezone(timedelta(hours=-6))
HOST = "alex-VirtualBox"
events = []
last_pid = 20000


def at(stamp):
    return datetime.fromisoformat(stamp).replace(tzinfo=TZ)


def add(t, pid, msg):
    events.append((t, pid, msg))


def attempt(t, user, ip, exists):
    global last_pid
    last_pid += random.randint(3, 40)
    port = random.randint(30000, 60000)
    if exists:
        add(t, last_pid, f"Failed password for {user} from {ip} port {port} ssh2")
    else:
        add(t, last_pid, f"Invalid user {user} from {ip} port {port}")
        add(t + timedelta(seconds=0.4), last_pid,
            f"Failed password for invalid user {user} from {ip} port {port} ssh2")


def accept(t, user, ip):
    global last_pid
    last_pid += random.randint(3, 40)
    port = random.randint(30000, 60000)
    add(t, last_pid, f"Accepted password for {user} from {ip} port {port} ssh2")


# 1. Fast bot: 60 guesses in about a minute, mostly nonexistent usernames
names = ["admin", "root", "test", "ubuntu", "oracle", "postgres", "user", "guest"]
start = at("2026-11-12T03:14:00")
for i in range(60):
    name = random.choice(names)
    attempt(start + timedelta(seconds=i * 1.1), name, "203.0.113.45", name == "root")

# 2. Slow guesser: one try about every 20 minutes against a real account, 6 hours
start = at("2026-11-12T08:00:00")
for i in range(18):
    attempt(start + timedelta(minutes=i * 20, seconds=random.randint(0, 90)),
            "alex", "198.51.100.77", True)

# 3. Honest typo: two failures, then a success seconds later
start = at("2026-11-12T19:30:00")
attempt(start, "alex", "192.0.2.10", True)
attempt(start + timedelta(seconds=6), "alex", "192.0.2.10", True)
accept(start + timedelta(seconds=14), "alex", "192.0.2.10")

# 4. Compromise: 12 failures against a real account, then a success
start = at("2026-11-12T22:41:00")
for i in range(12):
    attempt(start + timedelta(seconds=i * 9), "alex", "203.0.113.99", True)
accept(start + timedelta(seconds=115), "alex", "203.0.113.99")

events.sort(key=lambda e: e[0])
out = Path(__file__).with_name("attack-auth.log")
with out.open("w", encoding="utf-8", newline="\n") as f:
    for t, pid, msg in events:
        f.write(f"{t.isoformat(timespec='microseconds')} {HOST} sshd-session[{pid}]: {msg}\n")
print(f"wrote {len(events)} lines to {out}")