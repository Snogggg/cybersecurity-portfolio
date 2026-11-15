"""Generate two SYNTHETIC logs for AuthWatch v3.
baseline-auth.log : a normal week for two accounts (used with --learn)
zerotrust-auth.log: stolen-credential login, root login from outside, a distributed
                    attack on root, a blocklisted IP, and log-poisoning attempts.
IPs come from the documentation ranges (RFC 5737) or private space."""

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(31)
TZ = timezone(timedelta(hours=-6))
HOST = "alex-VirtualBox"
KEYFP = "RSA SHA256:3k9Zr0pQhV1m2xYw8nLq5T7uBfJ4dCaEoGsHiKtNvXs"  # made up
pid = [30000]


def at(s):
    return datetime.fromisoformat(s).replace(tzinfo=TZ)


def line(t, p, msg):
    return (t, f"{t.isoformat(timespec='microseconds')} {HOST} sshd-session[{p}]: {msg}")


def accepted(rows, t, user, ip, method):
    pid[0] += random.randint(3, 40)
    port = random.randint(30000, 60000)
    tail = f": {KEYFP}" if method == "publickey" else ""
    rows.append(line(t, pid[0], f"Accepted {method} for {user} from {ip} port {port} ssh2{tail}"))


def failed(rows, t, user, ip, exists):
    pid[0] += random.randint(3, 40)
    port = random.randint(30000, 60000)
    if exists:
        rows.append(line(t, pid[0], f"Failed password for {user} from {ip} port {port} ssh2"))
    else:
        rows.append(line(t, pid[0], f"Invalid user {user} from {ip} port {port}"))
        rows.append(line(t + timedelta(seconds=0.4), pid[0],
                         f"Failed password for invalid user {user} from {ip} port {port} ssh2"))


def write(name, rows):
    rows.sort(key=lambda r: r[0])
    out = Path(__file__).with_name(name)
    with out.open("w", encoding="utf-8", newline="\n") as f:
        for _, text in rows:
            f.write(text + "\n")
    print(f"wrote {len(rows)} lines to {out}")


# ---- baseline: a normal week ----
rows = []
for d in range(8):
    day = at("2026-11-02T00:00:00") + timedelta(days=d)
    accepted(rows, day + timedelta(hours=random.randint(9, 11), minutes=random.randint(0, 59)),
             "alex", "192.0.2.10", "publickey")
    if d % 2 == 0:
        accepted(rows, day + timedelta(hours=random.randint(14, 17), minutes=random.randint(0, 59)),
                 "alex", "192.0.2.10", "publickey")
    accepted(rows, day + timedelta(hours=random.randint(8, 10), minutes=random.randint(0, 59)),
             "sam", "192.0.2.11", "publickey")
for d in (1, 3, 6):
    day = at("2026-11-02T00:00:00") + timedelta(days=d)
    accepted(rows, day + timedelta(hours=random.randint(19, 22), minutes=random.randint(0, 59)),
             "alex", "10.8.0.14", "publickey")
write("baseline-auth.log", rows)

# ---- zero-trust scenarios ----
rows = []
# normal logins that fit the baseline
accepted(rows, at("2026-11-12T09:41:12"), "alex", "192.0.2.10", "publickey")
accepted(rows, at("2026-11-12T20:30:05"), "alex", "10.8.0.14", "publickey")
accepted(rows, at("2026-11-12T08:55:40"), "sam", "192.0.2.11", "publickey")
# stolen password: ZERO failures, one clean success, new IP, 3 a.m., password instead of key
accepted(rows, at("2026-11-13T03:12:09"), "alex", "203.0.113.150", "password")
# root logs in from outside the allowlist, no failures
accepted(rows, at("2026-11-13T14:02:31"), "root", "198.51.100.200", "password")
# distributed attack: ONE failure per IP, 12 IPs, all against root
for i in range(12):
    failed(rows, at("2026-11-13T10:00:00") + timedelta(seconds=i * 100 + random.randint(0, 30)),
           "root", f"198.51.100.{30 + i}", True)
# a blocklisted source
failed(rows, at("2026-11-13T11:15:00"), "admin", "203.0.113.45", False)
# log poisoning: the username contains text that looks like another source IP
for i in range(3):
    pid[0] += 7
    t = at("2026-11-13T15:50:00") + timedelta(seconds=20 * i)
    rows.append(line(t, pid[0],
        f"Failed password for invalid user x from 192.0.2.10 port 22 ssh2 y from 203.0.113.250 port {40000 + i} ssh2"))
write("zerotrust-auth.log", rows)