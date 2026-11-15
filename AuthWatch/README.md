# AuthWatch

A read-only Python tool that analyzes SSH authentication logs and ranks what it finds, so an analyst can tell a mistyped password from a brute-force attempt, and can spot a stolen-credential login that has no failures at all.

**Status:** complete (v3)

## Overview
LinuxLens could only count failed logins, and a raw count cannot separate a typo from an attack. AuthWatch reads the pattern: source IP, accounts tried, speed, duration, and outcome. It only reads logs and never blocks anything. It writes *suggested* blocks for a human to review.

All sample logs in this repo are **synthetic**, except `samples/real-auth.log`, which holds my own `ssh fakeuser@localhost` tests from an Ubuntu VM. Synthetic IPs come from the RFC 5737 documentation ranges or private space, so none are real hosts.

## What it detects
| Area | Detection | Priority |
|---|---|---|
| Source IP | Success after 10+ failures on one account | CRITICAL |
| | Success after 3 to 9 failures | HIGH |
| | 15+ failures in 60s, or 40+ in 10 minutes | HIGH |
| | Blocklisted source | HIGH |
| | Low and slow: 10+ failures over 1+ hours | MEDIUM |
| | Mostly nonexistent usernames | MEDIUM |
| | Malformed usernames (log poisoning attempts) | MEDIUM |
| | 1 to 2 failures then a success | INFO (typo) |
| Account | Many IPs failing against one account (lower bar for root/admin) | MEDIUM / HIGH |
| Successful logins | Scored against a per-account baseline: new IP, unusual hour, new method, privileged account, not on allowlist, probed other accounts first | LOW to HIGH |

## How it works
- **Parsing:** reads ISO and classic syslog timestamps and `sshd` / `sshd-session` lines. The failure and success patterns are anchored at both ends, so a crafted username cannot change the source IP (log poisoning defense).
- **Zero-trust review:** every successful login is judged on context, even with zero failures. Several weak signals together raise the priority.
- **Baseline:** `--learn` records each account's normal IPs, hours, and login methods. It never learns logins after failure streaks, from blocklisted sources, or for privileged accounts.
- **Allowlist and blocklist:** CIDR ranges with labels. An allowlist lowers priority one level but never lowers anything involving a success after failures, because that can mean a compromised trusted host.
- **Threshold jitter:** thresholds shift up to 20% daily from a secret seed (`AUTHWATCH_SEED`). This is obscurity, so multiple time windows and a total-volume rule back it up.
- **Audit log:** each run appends a hash-chained record. Editing any entry breaks the chain, and `--verify-audit` finds the break.

## Usage



Sample generators: `samples/make_attack_log.py` and `samples/make_v3_logs.py`.

## Validation
| Test | Result |
|---|---|
| Real VM log (my localhost tests) | 9 failures, 1 IP, 100% invalid usernames: MEDIUM |
| Simulated attack log, 4 stories | Compromise CRITICAL, bot HIGH, slow guesser MEDIUM, typo INFO |
| Stolen credential: 1 clean success, 0 failures | HIGH (new IP, 03:00, password instead of key) |
| Root login from outside the allowlist | HIGH |
| 12 IPs, one failure each, all against root | HIGH distributed attack, though each IP alone looks harmless |
| Log poisoning (username containing a fake source IP) | Failures credited to the real source, not the allowlisted one |
| v3 on the v1/v2 attack log | Same top verdicts as v2 |
| Edited one character in the audit log | `--verify-audit` reported a break at entry 1 |

## Findings
- v2 only analyzed failures, so a stolen password with one clean login was invisible. v3 scores every success against a baseline.
- The one attacker that got in was slower than a typical bot. A speed-only rule would have missed it, and the outcome rule caught it.
- Per-IP analysis misses distributed attacks. The per-account rule catches them.
- Usernames in logs are attacker-controlled. Anchoring the parser fixed attribution.
- A script cannot make files uneditable or invisible. That is OS permissions (`chmod 600`, `chattr +a`, `auditd`), so AuthWatch checks for it and warns.

## Limitations
- Thresholds are heuristics tuned on data I generated, so the real false-positive rate is unknown.
- Baselines can be poisoned, and a first-seen account has no baseline.
- One log at a time. Cross-host patterns need a central view (a SIEM).
- SSH password and key logins only. No `sudo`, `su`, console, or web-app logins.
- Stolen SSH keys look like normal key logins from the usual IP, so only a baseline signal like a new IP can catch them.
- No geolocation, impossible-travel check, or IP reputation.
- Detection is after the fact. There is no real-time alerting or automatic response.
- The audit log is tamper-evident, not tamper-proof. An attacker who can rewrite the file can rebuild the chain, so store the latest hash elsewhere.
- Rotated and `.gz` logs are not read yet.
- File-permission checks run only on Linux.

## Next steps
- Impossible-travel detection and IP reputation lookups
- Read rotated and `.gz` logs
- Watch mode and JSON output
- Run against a real exposed host and tune the thresholds

## Notes and evidence
Detailed write-ups with screenshots:
- [V1 SSH Auth Log Parser](notes/V1%20SSH%20Auth%20Log%20Parser.md)
- [V2 Verdicts, Detection Rules, and Allowlist](notes/V2%20Verdicts%2C%20Detection%20Rules%2C%20and%20Allowlist.md)
- [V3 Zero-Trust Review of Successful Logins](notes/V3%20Zero-Trust%20Review%20of%20Successful%20Logins.md)
