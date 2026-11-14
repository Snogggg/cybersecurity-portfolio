#!/usr/bin/env python3
"""AuthWatch v1: parse SSH authentication logs and summarize failures
per source IP and per username.

Reads either Ubuntu log format:
  2026-11-11T20:11:20.016836-06:00 host sshd-session[14424]: ...   (ISO timestamps)
  Nov 11 20:11:20 host sshd[14424]: ...                            (classic syslog)
"""

import argparse
import re
from collections import defaultdict
from datetime import datetime

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+|[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd(?:-session)?\[\d+\]:\s+(?P<msg>.*)$"
)
# One "Failed password" line per guess. It says "invalid user" when the
# account does not exist, which is why we do not also count "Invalid user" lines.
FAILED_RE = re.compile(
    r"Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)


def parse_time(ts, year):
    if ts[0].isdigit():
        return datetime.fromisoformat(ts)
    return datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")


def parse_log(path, year):
    events, total, ignored = [], 0, 0
    # errors="replace": auth.log can contain non-text bytes (the same issue
    # that made grep say "binary file matches" in LinuxLens)
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            total += 1
            m = LINE_RE.match(raw.strip())
            if not m:
                ignored += 1
                continue
            msg = m["msg"]
            fm = FAILED_RE.search(msg)
            am = ACCEPTED_RE.search(msg)
            if fm:
                kind, hit = "failed", fm
            elif am:
                kind, hit = "accepted", am
            else:
                ignored += 1
                continue
            events.append({
                "time": parse_time(m["ts"], year),
                "kind": kind,
                "user": hit["user"],
                "ip": hit["ip"],
                "invalid": bool(kind == "failed" and fm["invalid"]),
            })
    return events, total, ignored


def fmt(t):
    return t.strftime("%m-%d %H:%M:%S")


def build_report(events, total, ignored, top):
    failed = [e for e in events if e["kind"] == "failed"]
    accepted = [e for e in events if e["kind"] == "accepted"]

    by_ip = defaultdict(lambda: {"fails": 0, "users": set(), "invalid": 0,
                                 "first": None, "last": None})
    by_user = defaultdict(lambda: {"fails": 0, "ips": set(), "invalid": False})
    for e in failed:
        s = by_ip[e["ip"]]
        s["fails"] += 1
        s["users"].add(e["user"])
        s["invalid"] += e["invalid"]
        s["first"] = min(s["first"], e["time"]) if s["first"] else e["time"]
        s["last"] = max(s["last"], e["time"]) if s["last"] else e["time"]
        u = by_user[e["user"]]
        u["fails"] += 1
        u["ips"].add(e["ip"])
        u["invalid"] = u["invalid"] or e["invalid"]

    out = [
        "AuthWatch report",
        "=" * 70,
        f"Lines read: {total} (ignored {ignored}: not SSH password events)",
        f"Failed logins: {len(failed)}   Accepted logins: {len(accepted)}   "
        f"Source IPs with failures: {len(by_ip)}",
        "",
        "Failures per source IP",
        "-" * 70,
        f"{'Source IP':<18}{'Fails':>6}{'Users':>7}{'Invalid':>9}  {'First seen':<15}{'Last seen':<15}",
    ]
    rows = sorted(by_ip.items(), key=lambda kv: kv[1]["fails"], reverse=True)[:top]
    for ip, s in rows:
        out.append(f"{ip:<18}{s['fails']:>6}{len(s['users']):>7}{s['invalid']:>9}  "
                   f"{fmt(s['first']):<15}{fmt(s['last']):<15}")
    if not rows:
        out.append("(none)")

    out += ["", "Failures per username", "-" * 70,
            f"{'Username':<16}{'Fails':>6}{'IPs':>5}  Account"]
    rows = sorted(by_user.items(), key=lambda kv: kv[1]["fails"], reverse=True)[:top]
    for user, u in rows:
        out.append(f"{user:<16}{u['fails']:>6}{len(u['ips']):>5}  "
                   f"{'no such user' if u['invalid'] else 'exists'}")
    if not rows:
        out.append("(none)")

    out += ["", "Accepted logins", "-" * 70]
    for e in accepted[:top]:
        out.append(f"{fmt(e['time'])}  {e['user']} from {e['ip']}")
    if not accepted:
        out.append("(none)")
    return out


def main():
    ap = argparse.ArgumentParser(description="AuthWatch: SSH auth log analyzer")
    ap.add_argument("logfile")
    ap.add_argument("--year", type=int, default=datetime.now().year,
                    help="year for classic syslog timestamps (they omit it)")
    ap.add_argument("--top", type=int, default=10, help="rows per table")
    ap.add_argument("--out", help="also save the report to this file")
    args = ap.parse_args()

    events, total, ignored = parse_log(args.logfile, args.year)
    report = "\n".join(build_report(events, total, ignored, args.top))
    print(report)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report + "\n")


if __name__ == "__main__":
    main()