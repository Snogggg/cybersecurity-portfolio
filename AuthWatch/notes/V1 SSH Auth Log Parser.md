
## What it is
A Python script that reads a Linux authentication log and summarizes SSH login failures per **source IP** and per **username**. It is the follow-up to LinuxLens: the LinuxLens failed-logins check only produced a count, and a raw count can't tell a typo from a brute-force attack. AuthWatch looks at the **patterns** behind the count.

![screenshot](../screenshots/Pasted%20image%2020261113211707.png)

![screenshot](../screenshots/Pasted%20image%2020261113211722.png)

v1 only **counts and tabulates**. It gives no verdicts yet (that is v2).

## Why a count isn't enough
| Signal | Typo | Brute force |
|---|---|---|
| Volume and speed | 1 to 3 failures | Dozens or more, steady rhythm |
| Ending | Usually a success | Usually none (or one success at the end, the worst case) |
| Source IP | My own machine | Often unfamiliar |
| Usernames | One real account | Many names, often nonexistent |

Strongest tells: **invalid usernames** and **speed**. Machines are steady, humans are irregular.


- AuthWatch adds **who** (username) and **where from** (source IP) to LinuxLens's plain failure count.
- Fast attacker (203.0.113.99): 12 guesses in <2 min, succeeded. Noisy but still got in.
- Slow attacker (198.51.100.77): 18 guesses over 5.5 hours, never succeeded. Evades per-minute rules.
- Lockouts and rate limits (fail2ban) are separate from SIEM. A SIEM correlates events and alerts, and needs longer-window rules to catch low-and-slow.
- Design lesson: detect over multiple time windows, not just one.

## Where the data comes from
- Real log lines pulled from my VM: `sudo grep -a sshd /var/log/auth.log | tail -40`
- Saved as `samples/real-auth.log`. It contains my own `fakeuser` and `localuser` tests from 127.0.0.1.
- `samples/make_attack_log.py` generates `samples/attack-auth.log`, a **synthetic** log with four scenarios.
- The attack log IPs come from the documentation ranges (RFC 5737), so they are not real hosts. The README must say the log is simulated.

## What the real Ubuntu 26.04 log looked like
- **ISO timestamps:** `2026-11-11T20:11:15-06:00`, not the classic `Nov 11 20:11:15`. The parser reads both.
- **Process name:** `sshd-session[pid]`, not plain `sshd`.
- **Valid vs. invalid account:** `Failed password for alex` (exists) vs. `Failed password for invalid user fakeuser` (doesn't exist). That one phrase is the "invalid username" tell.
- **Noise:** PAM lines, `Connection closed`, and my own `sudo` command are not login events. The parser ignores them but counts them as "ignored" instead of dropping them silently.

## How the parser works
1. **Regex 1** pulls the timestamp and message out of each `sshd` line.
2. **Regex 2** matches `Failed password for [invalid user] <user> from <ip> port <n>`.
3. **Regex 3** matches `Accepted <method> for <user> from <ip> port <n>`.
4. Only the `Failed password` line is counted as a failure. The separate `Invalid user` line is **not** counted, or each guess would be double-counted.
5. Events are grouped by IP and by username, tracking fail counts, distinct users, invalid count, and first/last time seen.
6. `errors="replace"` when opening the file handles non-text bytes. This is the same cause as the `grep: binary file matches` bug in LinuxLens (which was fixed there with `grep -a`).

**Usage:**
```
python authwatch.py samples\real-auth.log
python authwatch.py samples\attack-auth.log --top 5 --out report.txt
```

## Results on my real log
- 31 lines read, 22 ignored, **9 failed logins**, 0 accepted, 1 source IP (127.0.0.1)
- `fakeuser` 6 failures, `localuser` 3, both marked `no such user`

## Results on the simulated attack log
148 lines read, **92 failed logins, 2 accepted, 4 source IPs**.

| Source IP | Fails | Story | What gives it away |
|---|---|---|---|
| 203.0.113.45 | 60 | Fast bot | 60 guesses in ~65 seconds, 8 usernames, 54 invalid |
| 198.51.100.77 | 18 | Slow guesser | One try about every 20 minutes for 5.5 hours, easy to miss |
| 203.0.113.99 | 12 | Compromise | 12 failures about 9 seconds apart, then a success at 22:42:55 |
| 192.0.2.10 | 2 | Honest typo | 2 failures, then a success 8 seconds later |

- `alex` shows 32 failures from 3 IPs, marked `exists`.
- Accepted logins: `192.0.2.10` at 19:30:14 and `203.0.113.99` at 22:42:55.

## How to read it like an analyst
- **Start from accepted logins and work backward.** A failure is an attempt. A success is the moment something actually happened.
- **192.0.2.10:** 2 failures, then a success 8 seconds later. Looks like a typo.
- **203.0.113.99:** 12 failures at a steady rhythm, then a success. The 16-second gap before the success is the script landing on a working password. Escalate.
- **Failures against nonexistent users** are the strongest single signal. A human doesn't try `admin` on a box with no `admin` account.
- **A log pattern suggests intent, it doesn't prove it.** Confirm with IP reputation, expected addresses, and what the account did after logging in.
- **Next steps for a real incident:** check the account's activity after the success, look up the IP, reset the password and kill sessions, block the IP, and search other logs for the same IP.

## Problems I hit
- Two log lines per invalid-username guess means line count and failure count differ. Counting only the `Failed password` line avoids double-counting.

## Limitations (v1)
- Counts only. It gives no verdict on which IP is an attack.
- It parses SSH password events only (no key logins, `sudo`, or other services).
- The attack log is synthetic. The real log only contains my own localhost tests.
- It doesn't yet detect low-and-slow attacks, invalid-username ratios, or failures followed by a success.

## Next: v2 detection rules
1. **Fast volume:** many failures per minute from one IP
2. **Invalid-username ratio:** most guesses hit nonexistent accounts
3. **Low and slow:** steady failures spread over hours
4. **Failures then success:** graded by streak length (2 = typo, 12 = likely compromise)

Each IP gets a verdict (`LIKELY BRUTE FORCE`, `SUSPICIOUS`, `PROBABLY A TYPO`) with the reason shown. Thresholds sit at the top of the file because they are heuristics.

