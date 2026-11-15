

# AuthWatch v3: Zero-Trust Review of Successful Logins

## Why v3
v2 was **failure-centric**. It caught noisy attackers, but a stolen password produces **zero failures and one clean success**, which v2 never examined. v3 treats a successful login as something to **judge on context**, not trust by default.

AuthWatch still only **reads logs**. It never blocks anyone. It writes **suggested** blocks for a human to review.

## Zero trust, correctly stated
- Zero trust means **no login is trusted by default**. Each one is judged on context.
- It does **not** mean alert on every success. That would bury the real findings in noise.
- Zero trust is bigger than log analysis: verify explicitly (MFA, key-only SSH), least privilege, and **assume breach**.
- AuthWatch covers only "assume breach" (detection). Prevention (MFA, key-only SSH, VPN) matters more.

## What v3 adds

| Feature | What it does |
|---|---|
| **Per-account baseline** | `--learn` records each account's normal IPs, login hours, and methods in `baseline.json` |
| **Success review** | Every accepted login is scored against its baseline, even with zero failures |
| **Known vs. unknown split** | Report shows unknown sources first, then allowlisted ones |
| **CIDR allowlist with labels** | Ranges like `10.8.0.0/24 vpn`, not just single IPs |
| **Blocklist** | Raises priority for known-bad sources |
| **Account-level detection** | Many IPs failing against one account (distributed attack), with a lower bar for `root`/`admin` |
| **Streak gap reset** | A quiet gap (15 min) ends a failure streak, so an old typo no longer counts toward a streak |
| **Multiple time windows** | 60s, 10 min, and total-volume rules, so staying just under one limit isn't enough |
| **Anchored parsing** | Defends against log poisoning (see below) |
| **Threshold jitter** | Each threshold shifts up to ±20% daily from a secret seed |
| **File-permission checks** | Warns if its own files or the log are too open |
| **Hash-chained audit log** | Records every run so tampering is detectable |

## Signals scored on every successful login

| Signal | Points | Meaning |
|---|---|---|
| New source IP for this account | +2 | The account has never logged in from there |
| Unusual hour | +1 | Outside the account's usual hours (needs 5+ logins of history) |
| New login method | +1 | Password where the account always uses a key |
| Privileged account (`root`/`admin`) | +2 | Higher stakes |
| Source not on the allowlist | +1 | Only checked when an allowlist is loaded |
| Privileged login from outside the allowlist | +2 | Extra |
| Same IP failed against other accounts first | +2 | Probing before the success |
| Blocklisted source | +3 | Known bad |

**Priority from score:** 5+ HIGH, 3 to 4 MEDIUM, 2 LOW, below 2 not listed.
Each signal alone is weak (people travel and work late). **Several together** raise the priority, the same idea as speed + accounts + outcome in v2.

## The baseline, and how it can fail
- `--learn` builds profiles from a trusted period of logs.
- **Never learned:** logins after failure streaks, blocklisted sources, and privileged accounts. Otherwise an attacker's login could become "normal".
- Limits:
  - A baseline learned from an already-compromised account treats the attacker as normal.
  - Travel, new devices, and VPN changes cause false positives.
  - It needs enough history. Accounts with no baseline are listed as "no baseline yet".

## What a Python script can and can't do
| My request | In the script | Real enforcement (OS level) |
|---|---|---|
| Protect and hide the files | **Checks** permissions and warns | `chmod 600`, `sudo chattr +a` on the audit file, `auditd` rule `-w /var/log/auth.log -p wa`, ship logs to a remote collector |
| Log when the tool is used | Hash-chained audit entry per run (time, user, host, SHA-256 of the log and config files) | Store the latest hash off the machine |
| Random thresholds | Daily jitter from `AUTHWATCH_SEED` | Keep the seed secret, set it as an environment variable, not on the command line |
| Block bad IPs | `--emit-blocklist` writes **suggestions** | Review, then `sudo ufw deny from <ip>` |
| Trust only the right IPs | CIDR allowlist with labels | VPN plus MFA, so identity comes from the login, not the address |

A script can't make a file uneditable or invisible. That's the operating system's job.

## Design points

**IP spoofing.** For SSH it's mostly **not** the risk. TCP needs a completed handshake, so a spoofed address can't log in. The real risks are:
- an attacker on a **compromised host inside a trusted range**
- a **shared NAT address** that trusts everyone behind it

A VPN helps because SSH is reachable only through it, so the VPN login (certificate plus MFA) establishes identity. An IP is still a weak trust signal, so v3 also checks behavior.

**Log poisoning.** The username in a log line is attacker-controlled. A crafted username like `x from 192.0.2.10 port 22 ssh2 y` could make a line look like it came from a trusted IP. The fix is to anchor the regex at both ends with a greedy username, so the **last** `from <ip> port <n>` wins. Odd usernames are also flagged as `MALFORMED USERNAMES`.

**Allowlist rules.**
- It lowers priority one level, never hides anything.
- It does **not** lower anything involving a success after failures, because that is what a compromised trusted host looks like.

**Jitter is obscurity, not security.** It makes thresholds harder to guess, but the real fix for "stay just under the limit" is multiple windows plus a total-volume rule.

**Audit log.** Each entry stores the hash of the previous one, so editing any entry breaks the chain. It's tamper-**evident**, not tamper-proof: an attacker who can rewrite the whole file can rebuild the chain, so the latest hash should live somewhere else.

## Test data (all synthetic)
- `make_v3_logs.py` generates two logs:
  - `baseline-auth.log`: a normal week for `alex` and `sam`
  - `zerotrust-auth.log`: stolen-credential login, root login from outside, a distributed attack on root, a blocklisted IP, and log-poisoning attempts
- IPs come from the RFC 5737 documentation ranges or private space, so none are real hosts.
- The README must say these logs are simulated.

## Commands
```
python samples\make_v3_logs.py
python authwatch.py samples\baseline-auth.log --baseline samples\baseline.json --learn
python authwatch.py samples\zerotrust-auth.log --baseline samples\baseline.json --allowlist samples\allowlist.txt --blocklist samples\blocklist.txt --audit-log samples\audit.jsonl --emit-blocklist samples\suggested-blocklist.txt
python authwatch.py --verify-audit samples\audit.jsonl
```
![screenshot](../screenshots/Pasted%20image%2020261114210359.png)
## Expected results (tick after verifying)
- [ ] Learn step: about 23 logins for 2 accounts, 0 skipped
- [ ] `alex` from `203.0.113.150` at 03:12 by password: **HIGH**, with **zero failures**. Signals: new IP, unusual hour, new method, not on allowlist
- [ ] `root` from `198.51.100.200`: **HIGH**, privileged login from outside the allowlist, no baseline for root
- [ ] The 3 normal logins fit the baseline and are not listed
- [ ] Account-level: `root` **HIGH, DISTRIBUTED ATTACK ON PRIVILEGED ACCOUNT** (12 IPs, one failure each, each IP alone looks harmless)
- [ ] `203.0.113.45`: **HIGH, BLOCKLISTED SOURCE**
- [ ] `203.0.113.250`: **MEDIUM, MALFORMED USERNAMES**
- [ ] Log poisoning: **no** failures attributed to `192.0.2.10` (if there are, the regex fix failed)
- [ ] `--verify-audit`: "Audit log OK: hash chain intact"
- [ ] Tamper test: change one character in `audit.jsonl`, and `--verify-audit` reports where the chain breaks
- [ ] Regression: v3 on `attack-auth.log` keeps the same top verdicts as v2

(These are derived by hand from the generator logic, not from a run, so exact counts may differ. The verdicts are the target.)

## Weaknesses that remain
- **Baselines can be poisoned**, and an account first seen during an attack has no baseline.
- **Per-IP and per-account only.** Cross-host patterns need a central view (SIEM).
- **Heuristic thresholds**, tuned on data I generated. The real false-positive rate is unknown.
- **SSH password and key logins only.** No `sudo`, `su`, console, or web-app logins.
- **Stolen SSH keys** produce a normal key login from the usual IP. Only a baseline signal like a new IP can catch that.
- **No geolocation, impossible-travel check, or IP reputation.** Those need outside data.
- **After the fact.** There's no real-time alerting or automatic response (fail2ban, lockout).
- **Whoever can edit the allowlist or baseline can blind it.** Protect those files and review changes.
- **Rotated and `.gz` logs aren't read yet.**



