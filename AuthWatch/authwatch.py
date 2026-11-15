#!/usr/bin/env python3
"""AuthWatch v3: SSH auth log analysis with a zero-trust review of successful logins.

New in v3: per-account baseline, review of every success, known/unknown source split,
CIDR allowlist and blocklist, per-account (distributed / privileged) detection,
streak gap reset, multiple time windows, anchored parsing (log-poisoning defense),
secret threshold jitter, file-permission checks, and a hash-chained audit log.
AuthWatch only READS logs. It never blocks anything.
"""

import argparse
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import stat
from collections import defaultdict
from datetime import date, datetime, timezone

# ---- Detection thresholds (heuristics; jittered if AUTHWATCH_SEED is set) ----
BASE = {
    "FAST_PEAK": 15,         # failures inside FAST_WINDOW
    "MID_PEAK": 40,          # failures inside MID_WINDOW
    "VOLUME_FAILS": 100,     # total failures from one IP
    "SLOW_MIN_FAILS": 10,    # low and slow: failures...
    "SLOW_MIN_SECONDS": 3600,  # ...spread over at least this long
    "INVALID_MIN_FAILS": 5,
    "COMPROMISE_STREAK": 10,
    "REVIEW_STREAK": 3,
    "DIST_IPS": 10,          # distinct IPs failing against one normal account
    "PRIV_DIST_IPS": 5,      # ...against a privileged account
}
FAST_WINDOW = 60
MID_WINDOW = 600
DIST_WINDOW = 3600
STREAK_GAP = 900             # a quiet gap this long ends a failure streak
INVALID_RATIO = 0.5
JITTER = 0.20
MIN_BASELINE = 5             # logins needed before the hour check is used
PRIVILEGED = {"root", "admin", "administrator"}
PRIORITY = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
# -----------------------------------------------------------------------------

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+|[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd(?:-session)?\[\d+\]:\s+(?P<msg>.*)$"
)
# Anchored at both ends, greedy username: the LAST "from <ip> port <n>" wins, so a
# username containing fake "from ..." text cannot change the source IP.
FAILED_RE = re.compile(
    r"^Failed password for (?P<invalid>invalid user )?(?P<user>.+) from (?P<ip>\S+) port \d+(?: ssh\d)?$"
)
ACCEPTED_RE = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>.+) from (?P<ip>\S+) port \d+(?: ssh\d)?(?::.*)?$"
)
USER_OK = re.compile(r"[A-Za-z0-9._$@-]{1,64}")


def make_thresholds(seed):
    th = {}
    for name, base in BASE.items():
        if not seed:
            th[name] = base
            continue
        digest = hmac.new(seed.encode(), f"{name}:{date.today().isoformat()}".encode(),
                          hashlib.sha256).digest()
        frac = int.from_bytes(digest[:4], "big") / 0xFFFFFFFF
        th[name] = max(2, round(base * (1 + JITTER * (2 * frac - 1))))
    return th


def safe(s, n=40):
    s = s.encode("unicode_escape").decode("ascii")
    return s if len(s) <= n else s[:n] + "..."


def fmt(t):
    return t.strftime("%m-%d %H:%M:%S")


def parse_time(ts, year):
    if ts[0].isdigit():
        t = datetime.fromisoformat(ts)
        return t if t.tzinfo else t.astimezone()
    return datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S").astimezone()


def parse_log(path, year):
    events, total, ignored, rejected = [], 0, 0, 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            total += 1
            m = LINE_RE.match(raw.strip())
            if not m:
                ignored += 1
                continue
            msg = m["msg"]
            fm = FAILED_RE.match(msg)
            am = None if fm else ACCEPTED_RE.match(msg)
            hit = fm or am
            if not hit:
                ignored += 1
                continue
            try:
                ipaddress.ip_address(hit["ip"])
            except ValueError:
                rejected += 1
                continue
            user = hit["user"]
            events.append({
                "time": parse_time(m["ts"], year),
                "kind": "failed" if fm else "accepted",
                "method": "password" if fm else am["method"],
                "user": user,
                "ip": hit["ip"],
                "invalid": bool(fm and fm["invalid"]),
                "odd": USER_OK.fullmatch(user) is None,
            })
    return events, total, ignored, rejected


def load_nets(path):
    nets = []
    if not path:
        return nets
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line:
                continue
            parts = line.split()
            try:
                nets.append((ipaddress.ip_network(parts[0], strict=False),
                             parts[1] if len(parts) > 1 else ""))
            except ValueError:
                print(f"warning: skipping bad entry {parts[0]!r} in {path}")
    return nets


def match(ip, nets):
    addr = ipaddress.ip_address(ip)
    for net, label in nets:
        if addr in net:
            return label or str(net)
    return None


def load_baseline(path):
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {"users": {}}


def secure_write(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    if os.name != "nt":
        os.chmod(path, 0o600)


def save_baseline(path, base):
    for p in base["users"].values():
        p["ips"].sort()
        p["hours"].sort()
        p["methods"].sort()
    secure_write(path, json.dumps(base, indent=2, sort_keys=True) + "\n")


def peak_in_window(times, seconds):
    best, lo = 0, 0
    for hi in range(len(times)):
        while (times[hi] - times[lo]).total_seconds() > seconds:
            lo += 1
        best = max(best, hi - lo + 1)
    return best


def success_context(events):
    """For each accepted login: failures right before it (same IP and account, a quiet
    gap resets the streak) and other accounts probed from the same IP in the last hour."""
    streaks, recent, out = {}, defaultdict(list), []
    for e in sorted(events, key=lambda x: x["time"]):
        key = (e["ip"], e["user"])
        if e["kind"] == "failed":
            c = streaks.get(key)
            if c is None:
                c = streaks[key] = [0, e["time"]]
            elif (e["time"] - c[1]).total_seconds() > STREAK_GAP:
                c[0] = 0
            c[0] += 1
            c[1] = e["time"]
            recent[e["ip"]].append((e["time"], e["user"]))
        else:
            c = streaks.pop(key, None)
            streak = c[0] if c and (e["time"] - c[1]).total_seconds() <= STREAK_GAP else 0
            probed = sorted({u for t, u in recent[e["ip"]]
                             if 0 <= (e["time"] - t).total_seconds() <= 3600 and u != e["user"]})
            out.append({**e, "streak": streak, "probed": probed})
    return out


def learn_baseline(ctx, base, block, th):
    learned = skipped = 0
    for s in ctx:
        if (s["streak"] >= th["REVIEW_STREAK"] or match(s["ip"], block)
                or s["user"] in PRIVILEGED):
            skipped += 1
            continue
        p = base["users"].setdefault(s["user"], {"ips": [], "hours": [], "methods": [], "count": 0})
        if s["ip"] not in p["ips"]:
            p["ips"].append(s["ip"])
        if s["time"].hour not in p["hours"]:
            p["hours"].append(s["time"].hour)
        if s["method"] not in p["methods"]:
            p["methods"].append(s["method"])
        p["count"] += 1
        learned += 1
    return learned, skipped


def analyze_ip(ip, fails, succ, th, allow_label, block_label):
    times = sorted(e["time"] for e in fails)
    n = len(times)
    duration = (times[-1] - times[0]).total_seconds()
    peak1 = peak_in_window(times, FAST_WINDOW)
    peak10 = peak_in_window(times, MID_WINDOW)
    invalid = sum(e["invalid"] for e in fails)
    odd = sum(e["odd"] for e in fails)
    ratio = invalid / n
    after = [s for s in succ if s["streak"] > 0]

    findings, success_related = [], False
    for s in after:
        what = f"{s['streak']} failures against '{safe(s['user'])}', then a success at {fmt(s['time'])}"
        if s["streak"] >= th["COMPROMISE_STREAK"]:
            findings.append((4, "LIKELY COMPROMISE", what))
            success_related = True
        elif s["streak"] >= th["REVIEW_STREAK"]:
            findings.append((3, "REVIEW: SUCCESS AFTER FAILURES", what))
            success_related = True
    if peak1 >= th["FAST_PEAK"]:
        findings.append((3, "LIKELY BRUTE FORCE", f"{peak1} failures within {FAST_WINDOW}s"))
    elif peak10 >= th["MID_PEAK"]:
        findings.append((3, "LIKELY BRUTE FORCE", f"{peak10} failures within {MID_WINDOW // 60} minutes"))
    if n >= th["VOLUME_FAILS"]:
        findings.append((3, "HIGH VOLUME", f"{n} failures in total from this IP"))
    if (n >= th["SLOW_MIN_FAILS"] and duration >= th["SLOW_MIN_SECONDS"]
            and peak1 < th["FAST_PEAK"] and peak10 < th["MID_PEAK"]):
        findings.append((2, "SUSPICIOUS: LOW AND SLOW",
                         f"{n} failures spread over {duration / 3600:.1f} hours "
                         f"(never more than {peak1} per {FAST_WINDOW}s)"))
    if n >= th["INVALID_MIN_FAILS"] and ratio >= INVALID_RATIO:
        findings.append((2, "SUSPICIOUS: INVALID USERNAMES",
                         f"{ratio:.0%} of guesses hit nonexistent accounts ({invalid}/{n})"))
    if odd:
        findings.append((2, "SUSPICIOUS: MALFORMED USERNAMES",
                         f"{odd} username(s) look like crafted log text (possible log poisoning)"))
    if block_label:
        findings.append((3, "BLOCKLISTED SOURCE", f"IP is on the blocklist ({block_label})"))

    if not findings:
        if after:
            s = after[0]
            findings.append((0, "PROBABLY A TYPO",
                             f"{s['streak']} failure(s) against '{safe(s['user'])}', "
                             f"then a success at {fmt(s['time'])}"))
        else:
            findings.append((0, "LOW ACTIVITY", f"{n} failure(s), no success"))

    top = max(findings, key=lambda f: f[0])
    prio, verdict = top[0], top[1]
    reasons = [f[2] for f in findings]
    if prio >= 2 and not succ:
        reasons.append("no successful login from this IP (attempt only)")
    if allow_label:
        if success_related or prio == 4:
            reasons.append(f"allowlisted ({allow_label}) but NOT lowered: a success after failures "
                           "can mean a compromised trusted host")
        elif prio > 0:
            prio -= 1
            reasons.append(f"allowlisted ({allow_label}): priority lowered one level")
    return {"ip": ip, "fails": n, "prio": prio, "verdict": verdict, "reasons": reasons,
            "known": bool(allow_label), "blocked": bool(block_label)}


def analyze_users(fails_by_user, th):
    out = []
    for user, evs in fails_by_user.items():
        evs = sorted(evs, key=lambda e: e["time"])
        priv = user in PRIVILEGED
        need = th["PRIV_DIST_IPS"] if priv else th["DIST_IPS"]
        counts, best, lo = defaultdict(int), 0, 0
        for e in evs:
            counts[e["ip"]] += 1
            while (e["time"] - evs[lo]["time"]).total_seconds() > DIST_WINDOW:
                old = evs[lo]["ip"]
                counts[old] -= 1
                if counts[old] == 0:
                    del counts[old]
                lo += 1
            best = max(best, len(counts))
        if best >= need:
            out.append({
                "user": user, "priv": priv, "prio": 3 if priv else 2,
                "verdict": "DISTRIBUTED ATTACK" + (" ON PRIVILEGED ACCOUNT" if priv else ""),
                "reason": f"{best} different IPs failed against '{safe(user)}' within "
                          f"{DIST_WINDOW // 60} minutes (each IP alone looks harmless)",
                "ips": sorted({e["ip"] for e in evs}),
            })
    return sorted(out, key=lambda a: -a["prio"])


def review_success(s, base, allow, block, th):
    user, ip = s["user"], s["ip"]
    prof = base["users"].get(user)
    score, sig = 0, []
    if prof is None:
        sig.append("no baseline for this account (cannot compare with its normal behavior)")
    else:
        if ip not in prof["ips"]:
            score += 2
            sig.append(f"new source IP for this account ({len(prof['ips'])} known)")
        if prof["count"] >= MIN_BASELINE:
            allowed = {(h + d) % 24 for h in prof["hours"] for d in (-1, 0, 1)}
            if s["time"].hour not in allowed:
                score += 1
                sig.append(f"unusual hour ({s['time'].hour:02d}:00; usual "
                           f"{','.join(f'{h:02d}' for h in sorted(prof['hours']))})")
        if s["method"] not in prof["methods"]:
            score += 1
            sig.append(f"new login method ({s['method']}; usual: {', '.join(prof['methods'])})")
    unknown = bool(allow) and not match(ip, allow)
    priv = user in PRIVILEGED
    if priv:
        score += 2
        sig.append("privileged account")
    if unknown:
        score += 1
        sig.append("source is not on the allowlist")
    if priv and unknown:
        score += 2
        sig.append("privileged login from outside the allowlist")
    if s["probed"]:
        score += 2
        sig.append("this IP failed against other accounts first: "
                   + ", ".join(safe(u) for u in s["probed"][:5]))
    if s["streak"] >= th["REVIEW_STREAK"]:
        sig.append(f"preceded by {s['streak']} failures (see the source IP verdict)")
    b = match(ip, block)
    if b:
        score += 3
        sig.append(f"source IP is on the blocklist ({b})")
    prio = 3 if score >= 5 else 2 if score >= 3 else 1 if score >= 2 else 0
    return {"event": s, "score": score, "prio": prio, "signals": sig, "baselined": prof is not None}


def suggest_blocks(results, accts, allow, block):
    sugg = {}
    for r in results:
        if r["prio"] >= 3 and not r["known"] and not r["blocked"]:
            sugg[r["ip"]] = r["verdict"].lower()
    for a in accts:
        if a["priv"]:
            for ip in a["ips"]:
                if not match(ip, allow) and not match(ip, block):
                    sugg.setdefault(ip, f"part of distributed attack on '{safe(a['user'])}'")
    return sugg


def check_files(sensitive, logs):
    if os.name == "nt":
        return ["file-permission checks skipped on Windows; they apply on the Linux host"]
    notes = []
    for p in sensitive:
        if p and os.path.exists(p):
            mode = stat.S_IMODE(os.stat(p).st_mode)
            if mode & 0o077:
                notes.append(f"{p} has mode {mode:03o}; expected 600 (owner only)")
    for p in logs:
        if p and os.path.exists(p):
            mode = stat.S_IMODE(os.stat(p).st_mode)
            if mode & 0o002:
                notes.append(f"{p} is WORLD-WRITABLE (mode {mode:03o})")
            elif mode & 0o004:
                notes.append(f"{p} is world-readable (mode {mode:03o}); expected 640")
    return notes


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_audit(path, record):
    prev = "0" * 64
    if os.path.exists(path):
        last = None
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line
        if last:
            prev = json.loads(last)["hash"]
    entry = {**record, "prev": prev}
    entry["hash"] = hashlib.sha256((prev + json.dumps(entry, sort_keys=True)).encode()).hexdigest()
    with open(path, "a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    if os.name != "nt":
        os.chmod(path, 0o600)


def verify_audit(path):
    prev = "0" * 64
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            entry = json.loads(line)
            claimed = entry.pop("hash", "")
            if entry.get("prev") != prev:
                return False, n
            if hashlib.sha256((prev + json.dumps(entry, sort_keys=True)).encode()).hexdigest() != claimed:
                return False, n
            prev = claimed
    return True, 0


def build_report(info, results, accts, reviews, top):
    fails = info["fails"]
    out = [
        "AuthWatch report (v3)",
        "=" * 70,
        f"Lines read: {info['total']} (ignored {info['ignored']}: not SSH login events; "
        f"rejected {info['rejected']}: invalid IP)",
        f"Failed logins: {len(fails)}   Accepted logins: {info['nacc']}   "
        f"Source IPs with failures: {len(results)}",
        f"Odd usernames: {sum(e['odd'] for e in fails)} (possible probing or log poisoning)",
        f"Allowlist entries: {info['nallow']}   Blocklist entries: {info['nblock']}   "
        f"Baseline accounts: {info['nbase']}   Threshold jitter: {'ON' if info['jitter'] else 'OFF'}",
    ]
    out += [f"NOTE: {n}" for n in info["notes"]]

    out += ["", "Account-level findings", "-" * 70]
    if accts:
        for a in accts[:top]:
            out.append(f"[{PRIORITY[a['prio']]:<8}] account '{safe(a['user'])}'  {a['verdict']}")
            out.append(f"             - {a['reason']}")
    else:
        out.append("(none)")

    shown = [r for r in results if r["prio"] > 0]
    for title, known in (("Source IPs: UNKNOWN (not on allowlist)", False),
                         ("Source IPs: KNOWN (allowlisted)", True)):
        out += ["", title, "-" * 70]
        rows = [r for r in shown if r["known"] == known][:top]
        for r in rows:
            out.append(f"[{PRIORITY[r['prio']]:<8}] {r['ip']:<16} {r['verdict']}")
            out += [f"             - {x}" for x in r["reasons"]]
        if not rows:
            out.append("(none)")
    quiet = len(results) - len(shown)
    if quiet:
        out.append(f"({quiet} source IP(s) with only low activity not listed)")

    out += ["", "Successful logins: zero-trust review", "-" * 70]
    flagged = sorted([v for v in reviews if v["prio"] > 0], key=lambda v: -v["score"])
    for v in flagged[:top]:
        s = v["event"]
        out.append(f"[{PRIORITY[v['prio']]:<8}] {fmt(s['time'])}  {safe(s['user'])} from {s['ip']} "
                   f"({s['method']})  score {v['score']}")
        out += [f"             - {x}" for x in v["signals"]]
    if not flagged:
        out.append("(no successful login stood out)")
    fit = sum(1 for v in reviews if v["prio"] == 0 and v["baselined"])
    out.append(f"{fit} login(s) fit the account baseline.")
    nb = sorted({safe(v["event"]["user"]) for v in reviews if not v["baselined"]})
    if nb:
        out.append("No baseline yet for: " + ", ".join(nb))

    by_ip = defaultdict(lambda: {"fails": 0, "users": set(), "invalid": 0, "first": None, "last": None})
    by_user = defaultdict(lambda: {"fails": 0, "ips": set(), "invalid": False})
    for e in fails:
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
    out += ["", "Failures per source IP", "-" * 70,
            f"{'Source IP':<18}{'Fails':>6}{'Users':>7}{'Invalid':>9}  {'First seen':<15}{'Last seen':<15}"]
    for ip, s in sorted(by_ip.items(), key=lambda kv: kv[1]["fails"], reverse=True)[:top]:
        out.append(f"{ip:<18}{s['fails']:>6}{len(s['users']):>7}{s['invalid']:>9}  "
                   f"{fmt(s['first']):<15}{fmt(s['last']):<15}")
    out += ["", "Failures per username", "-" * 70, f"{'Username':<42}{'Fails':>6}{'IPs':>5}  Account"]
    for user, u in sorted(by_user.items(), key=lambda kv: kv[1]["fails"], reverse=True)[:top]:
        out.append(f"{safe(user):<42}{u['fails']:>6}{len(u['ips']):>5}  "
                   f"{'no such user' if u['invalid'] else 'exists'}")
    return out


def main():
    ap = argparse.ArgumentParser(description="AuthWatch v3: SSH auth log analyzer (read-only)")
    ap.add_argument("logfile", nargs="?")
    ap.add_argument("--year", type=int, default=datetime.now().year,
                    help="year for classic syslog timestamps (they omit it)")
    ap.add_argument("--top", type=int, default=10, help="rows per section")
    ap.add_argument("--allowlist", help="known-good networks (CIDR ok), one per line")
    ap.add_argument("--blocklist", help="known-bad networks, one per line")
    ap.add_argument("--baseline", help="JSON file of each account's normal logins")
    ap.add_argument("--learn", action="store_true", help="update --baseline from this log, then exit")
    ap.add_argument("--emit-blocklist", help="write SUGGESTED blocks for human review")
    ap.add_argument("--audit-log", help="append a hash-chained record of this run")
    ap.add_argument("--verify-audit", help="check an audit log's hash chain, then exit")
    ap.add_argument("--out", help="also save the report (mode 600 on Linux)")
    args = ap.parse_args()

    if args.verify_audit:
        ok, n = verify_audit(args.verify_audit)
        print("Audit log OK: hash chain intact" if ok else f"AUDIT LOG TAMPERED: chain breaks at entry {n}")
        raise SystemExit(0 if ok else 2)
    if not args.logfile:
        ap.error("logfile is required")
    if args.learn and not args.baseline:
        ap.error("--learn needs --baseline FILE")

    seed = os.environ.get("AUTHWATCH_SEED")
    th = make_thresholds(seed)
    events, total, ignored, rejected = parse_log(args.logfile, args.year)
    allow, block = load_nets(args.allowlist), load_nets(args.blocklist)
    baseline = load_baseline(args.baseline)
    ctx = success_context(events)

    def audit(mode, counts):
        if not args.audit_log:
            return
        rec = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "mode": mode,
               "host": socket.gethostname(), "log": args.logfile,
               "log_sha256": sha256_file(args.logfile), "counts": counts}
        try:
            rec["user"] = getpass.getuser()
        except Exception:
            rec["user"] = "unknown"
        for name in ("allowlist", "blocklist", "baseline"):
            p = getattr(args, name)
            if p and os.path.exists(p):
                rec[f"{name}_sha256"] = sha256_file(p)
        write_audit(args.audit_log, rec)

    if args.learn:
        learned, skipped = learn_baseline(ctx, baseline, block, th)
        save_baseline(args.baseline, baseline)
        print(f"Learned {learned} login(s) for {len(baseline['users'])} account(s); skipped {skipped} "
              "(after failure streaks, blocklisted sources, and privileged accounts are never learned).")
        audit("learn", {"learned": learned, "skipped": skipped})
        return

    fails = [e for e in events if e["kind"] == "failed"]
    fails_by_ip, fails_by_user, succ_by_ip = defaultdict(list), defaultdict(list), defaultdict(list)
    for e in fails:
        fails_by_ip[e["ip"]].append(e)
        fails_by_user[e["user"]].append(e)
    for s in ctx:
        succ_by_ip[s["ip"]].append(s)

    results = [analyze_ip(ip, evs, succ_by_ip.get(ip, []), th, match(ip, allow), match(ip, block))
               for ip, evs in fails_by_ip.items()]
    results.sort(key=lambda r: (-r["prio"], -r["fails"]))
    accts = analyze_users(fails_by_user, th)
    reviews = [review_success(s, baseline, allow, block, th) for s in ctx]

    info = {"total": total, "ignored": ignored, "rejected": rejected, "fails": fails,
            "nacc": len(ctx), "nallow": len(allow), "nblock": len(block),
            "nbase": len(baseline["users"]), "jitter": bool(seed),
            "notes": check_files([args.allowlist, args.blocklist, args.baseline, args.audit_log],
                                 [args.logfile])}
    report = "\n".join(build_report(info, results, accts, reviews, args.top))
    print(report)
    if args.out:
        secure_write(args.out, report + "\n")

    if args.emit_blocklist:
        sugg = suggest_blocks(results, accts, allow, block)
        lines = ["# SUGGESTED by AuthWatch. Review every entry; AuthWatch never blocks anything.",
                 "# IP blocks can hit shared NAT addresses, and attackers rotate IPs."]
        lines += [f"{ip}  suggested  # {why}" for ip, why in sorted(sugg.items())]
        secure_write(args.emit_blocklist, "\n".join(lines) + "\n")
        print(f"\nWrote {len(sugg)} suggested block(s) to {args.emit_blocklist} (review before use)")

    audit("analyze", {"ip_findings_high_or_above": sum(r["prio"] >= 3 for r in results),
                      "account_findings": len(accts),
                      "logins_flagged": sum(v["prio"] > 0 for v in reviews)})


if __name__ == "__main__":
    main()