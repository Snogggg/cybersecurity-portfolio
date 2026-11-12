# LinuxLens

A read-only Bash script that audits an Ubuntu machine's security configuration and produces a graded PASS / WARN / FAIL report. Every finding that isn't a PASS includes why it matters and how to fix it.

**Status:** complete (v1)

## Overview
LinuxLens checks the settings attackers go after first: remote login, admin rights, file permissions, network exposure, patching, and signs of password guessing. It only reports problems and never changes the system, so it is safe to run on a machine you care about.

Built and tested in an Ubuntu 26.04 LTS VM (VirtualBox, 4 GB RAM, 40 GB disk) used as an isolated lab.

## What it checks
| Area | Check | Grading |
|---|---|---|
| **SSH** | Root login (`PermitRootLogin`) | `no` = PASS, key only = WARN, `yes` = FAIL |
| | Password login (`PasswordAuthentication`) | enabled = WARN |
| **Accounts** | Sudo group size | more than 1 member = WARN |
| | `/etc/shadow` and `/etc/passwd` permissions | exposed or writable by non-root = FAIL |
| **Filesystem** | World-writable files and directories (no sticky bit) | any found = WARN |
| | Unexpected SUID binaries (allowlist) | any found = WARN |
| **Network** | Firewall (ufw) status | inactive = WARN |
| | Services listening on the network besides SSH | any found = WARN |
| **Patching and monitoring** | Pending updates | any = WARN, security updates pending = FAIL |
| | Failed SSH logins (count, invalid usernames, top source IP) | 10+ = WARN, 50+ = FAIL |

That is 10 checks producing 12 result lines per run.

## How it was validated
Each check was tested by breaking the VM on purpose and confirming the grade changed, then restoring the setting.

| Test | Result |
|---|---|
| Clean baseline | 10 pass, 2 warn, 0 fail |
| `PermitRootLogin yes` | SSH root check WARN to **FAIL**, then **PASS** after setting `no` |
| `chmod 777` on a test file | World-writable check flagged the file |
| Fake SUID copy of `cat` | SUID check flagged the binary |
| `chmod 644 /etc/shadow` | **FAIL**: password hashes readable by every user |
| `python3 -m http.server 8080` | Ports check listed `tcp/8080` |
| Firewall off, then on | WARN to PASS (SSH allowed first, then enabled) |
| 35 pending updates (32 security) | **FAIL**, PASS after `apt upgrade` |
| 12 failed SSH logins as a nonexistent user | WARN naming 4 invalid-username attempts, source 127.0.0.1 |

All test changes were reverted after each run.

## Findings and lessons
- **Default Ubuntu was reasonable but not hardened:** root could log in over SSH with a key, password login was on, the firewall was off, and 35 updates (32 security) were pending on a fresh install.
- **False positives need tuning:** the first SUID scan flagged `pppd`, `ntfs-3g`, and `sudo.ws`. I verified each with `dpkg -S` (package ownership) and added them to the allowlist.
- **A check that has never failed isn't proven:** the failed-logins check initially reported 0 while the journal showed 12 failures. `grep` was printing "binary file matches" for `auth.log` instead of the lines. Fixed with `grep -a`.
- **Stale data gives false assurance:** the update check read a stale package list and saw 1 pending update instead of 35 until `apt update` was run.
- **Why disable root SSH login:** attackers already know the username `root`. Disabling it forces them to compromise a normal account first and escalate separately, which adds a step and leaves more evidence in the logs.

## Usage
```bash
chmod +x linuxlens.sh
sudo ./linuxlens.sh
```
Root is required to read the effective SSH configuration and `/etc/shadow`. The report prints to the screen and is saved to `linuxlens-report.txt`.

## Limitations
- Audits only the machine it runs on. No network scanning.
- Update counts come from the local package list, so they are only as current as the last `apt update`. The script does not run `apt update` itself because it is read-only.
- The ports check lists listening services but does not account for firewall rules.
- Failed-login counts depend on log retention, and the WARN persists until the log rotates. Thresholds (10 and 50) are heuristics, not a standard.
- The SUID allowlist is tuned to Ubuntu 26.04 and needs adjusting for other distributions.
- SSH checks read global settings and do not account for per-user `Match` overrides.
- The permission check does not inspect file contents, such as an extra UID 0 account inside `/etc/passwd`.
- The sudo group check does not read `/etc/sudoers`. A WARN means "investigate", not "compromised".

## Next steps
- Make the ports check firewall-aware
- Add a check for extra UID 0 accounts and `/etc/sudoers` rules
- Set up SSH keys, then disable password login
- Add SGID binaries and file capabilities
- Add configurable thresholds and a markdown report export

## Notes and evidence
Detailed write-ups with screenshots are in the `notes` folder:
- [SSH root login check](notes/LinuxLens%20SSH%20root%20login%20check.md)
- [File permission and SUID checks](notes/LinuxLens%20File%20Permission%20and%20SUID%20Checks.md)
- [Network exposure, patching, and failed logins](notes/LinuxLens%20Network%20Exposure%2C%20Patching%2C%20and%20Failed%20Logins%20%28Part%202%29.md)