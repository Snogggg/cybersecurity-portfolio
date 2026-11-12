![screenshot](../screenshots/Pasted%20image%2020261111193209.png)



Adding another attack surface of http in the list of ports open to the network.
![screenshot](../screenshots/Pasted%20image%2020261111193352.png)


Turning the Firewall On- This fixes the issue of what goes in but still does not FIX the issue of listening. So we need to enhance this. 

![screenshot](../screenshots/Pasted%20image%2020261111194850.png)


Check for security updates, software has bugs where vendors release patches and a machine with a pending update is a known vulnerability where gives attackers something to look for.
![screenshot](../screenshots/Pasted%20image%2020261111195144.png)




![screenshot](../screenshots/Pasted%20image%2020261111195420.png)

Report of the updates that still need to be implemented.
![screenshot](../screenshots/Pasted%20image%2020261111195736.png)


After I implemented all the new patches 

![screenshot](../screenshots/Pasted%20image%2020261111195903.png)




Now account login failure via logs



![screenshot](../screenshots/Pasted%20image%2020261111201701.png)



## What I added
Four read-only checks to the audit script. They only **report**. The only changes to the VM were fixes I made by hand to prove each check flips from bad to good.

1. **Firewall status** (ufw)
2. **Listening ports** (what is exposed to the network)
3. **Pending package updates**
4. **Failed SSH logins**

Together they answer: what can attackers reach, is anything guarding it, is the software patched, and is someone already trying to get in?

---

## Check 1: Listening ports

**Command:** `sudo ss -tulpn`

| Flag | Meaning |
|---|---|
| `-t` | TCP sockets |
| `-u` | UDP sockets |
| `-l` | only **listening** sockets (waiting for connections) |
| `-p` | show the **program** that owns each one |
| `-n` | show port **numbers**, not names |

**How to tell if a port is exposed:** read the **Local Address** column.

| Local address | Meaning | Exposed? |
|---|---|---|
| `0.0.0.0`, `[::]`, `*` | listening on **all interfaces** | **Yes** |
| `127.x.x.x`, `[::1]` | loopback, this machine only | No |

(The Peer Address `*` just means "no connection yet." Look at Local Address.)

**What I found on my VM**
| Port | Program | Exposed? |
|---|---|---|
| 22/tcp | SSH | Yes (on purpose) |
| 5353/udp | avahi-daemon (local network discovery) | Yes |
| random high port | Firefox (temporary/ephemeral, changes each time) | Yes, while Firefox is open |
| 53 | systemd-resolved (local DNS resolver) | No, local only |
| 323 | chronyd (time sync) | No, local only |
| 631 | cupsd (printing) | No, local only |

**Grading:** WARN if anything other than SSH is exposed. Localhost-only ports are ignored.

**Why it matters:** every exposed port is a door. The program behind it can have bugs, weak settings, or default passwords. The question for each one is: *do I need this reachable from the network?*

**Break-it test:** `python3 -m http.server 8080 --bind 0.0.0.0` opened **tcp/8080**, an unencrypted web server that shares the whole folder with no login. The script listed it. Ctrl+C stopped it and the port disappeared.
- Port 80 = standard HTTP (needs root to bind). 8080 = the common alternate port any user can open.
- Binding to `127.0.0.1` instead would have been local only, and not flagged.

---

## Check 2: Firewall (ufw)

**ufw** = Uncomplicated Firewall, Ubuntu's simple front end for the Linux firewall.

- `ufw status` shows whether it's on and which rules exist.
- Default when enabled: **deny incoming, allow outgoing**.
- **Order matters:** allow SSH **first**, then enable. Enabling with no rules blocks all incoming traffic, including SSH, and can lock you out of a remote machine.

```
sudo ufw allow ssh
sudo ufw enable
```

**Grading:** inactive = WARN, active = PASS.

**Result:** WARN to PASS after enabling.

**Ports vs. firewall (important distinction):**
- `ss` answers **what doors exist** (services listening).
- `ufw` answers **who guards them** (what is allowed through).
- The firewall blocks traffic to a port but does **not** stop the service from listening, so the ports WARN stays. This is **defense in depth**. To remove the WARN for real, stop the service (`sudo systemctl disable --now avahi-daemon`) or accept the risk on purpose.

---

## Check 3: Pending security updates

**Why it matters:** software has bugs, and vendors publish patches. An unpatched machine is running **known, published vulnerabilities** that attackers actively scan for.

**How the script counts them:**
```
apt-get -s upgrade | grep -c '^Inst'            # all pending updates
apt-get -s upgrade | grep '^Inst' | grep -ci security   # from security repos
```
- `-s` = **simulate**. It shows what would be installed and changes nothing.
- Each `Inst` line is one package that would be upgraded.

**Grading**
| Condition | Grade |
|---|---|
| 0 pending | PASS |
| Pending, none from security | WARN |
| Any from a security repo | **FAIL** |

**My results**
- First run: **35 pending, 32 from security**, so **FAIL**.
- Fix: `sudo apt update && sudo apt upgrade -y`
- After: `[PASS] No pending package updates`.

**Lesson learned:** my first check only saw 1 pending package. The local package list was stale. `sudo apt update` refreshed it and revealed 35. The script reads the local list, so it's only as current as the last `apt update`. It doesn't run `apt update` itself, because that would change the system and LinuxLens is read-only.

---

## Check 4: Failed SSH logins

**Where the data lives**
- `/var/log/auth.log` (permissions 640, `syslog:adm`, same least-privilege idea as shadow)
- The systemd journal: `journalctl --since "7 days ago"`
- `|` (pipe) feeds one command's output into the next. `grep -ci` searches case-insensitively and prints a count.

**Typo vs. brute force:** a single failure means nothing. The **pattern** matters.

| Signal | Typo | Brute force |
|---|---|---|
| Volume and speed | 1 to 3, then success | Dozens or thousands, many per second |
| Ending | Usually a successful login | Usually never succeeds (or succeeds once at the end, the worst case) |
| Source IP | My own machine | Often unfamiliar or external |
| Usernames | One real name | Many names (`root`, `admin`, `test`), often nonexistent |
| Timing | While I was at the keyboard | Odd hours, steady and machine-like |

Strongest tells: **invalid usernames** and **speed**.

**What the script does:** counts only **SSH** failures (so my own `sudo` typos are ignored), counts `Invalid user` attempts, and reports the top source IP.

| Condition | Grade |
|---|---|
| fewer than 10 failures | PASS |
| 10 to 49 | WARN |
| 50 or more | FAIL |

These thresholds are a heuristic, not a standard. A public server would see hundreds a day from bots.

**Break-it test:** ran `ssh fakeuser@localhost` 4 times and typed wrong passwords (Linux shows nothing as you type a password, that's normal).
- Result: `[WARN] Elevated SSH login failures: 12 SSH password failure(s), 4 invalid-username attempt(s), top source 127.0.0.1 (12)`
- 12 = 4 connections x 3 guesses. 4 invalid usernames = 4 connections to `fakeuser`, which doesn't exist. Source is my own VM.

**Bug I found:** the check first reported **0 failures** even though the journal showed 12. Cause: `grep: /var/log/auth.log: binary file matches`. The log contains a few non-text bytes, so plain `grep` printed that one-line message instead of the real lines. Fix: **`grep -a`** forces text mode. Lesson: a check that has never been seen to fail isn't proven, which is why break-it tests matter.

**Defenses (not built, worth knowing):** fail2ban (auto-ban an IP after N failures), a SIEM (correlates patterns across many machines).

---

## Results summary
| State | Result |
|---|---|
| Clean baseline | 10 pass, 2 warn, 0 fail |
| After break-it tests | 9 pass, 3 warn, 0 fail |

Remaining WARNs: SSH password login (needs SSH keys first) and listening ports (a service I review and accept).

## Limitations
- Updates are read from the local package list, so they're only as current as the last `apt update`.
- The ports check doesn't account for firewall rules.
- Failed-login counts depend on log retention, and the WARN stays until the log rotates.
- Count thresholds are heuristics.
- It audits one machine only.

