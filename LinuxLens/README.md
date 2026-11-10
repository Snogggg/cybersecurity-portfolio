# LinuxLens

Linux security audit script and report generator.

**Status:** in progress

## Summary: LinuxLens SSH audit (Ubuntu VM)

### What I did
- Built an Ubuntu 26.04 LTS virtual machine in VirtualBox (4 GB RAM, 40 GB disk) as a safe lab.
- Updated the system and installed the SSH server so there was something real to audit.
- Wrote `linuxlens.sh`, a read-only Bash script that checks three things:
  1. Can root log in over SSH?
  2. Is SSH password login enabled?
  3. How many users are in the sudo group?
- Each check gets a PASS, WARN, or FAIL, plus a "why it matters" and a "how to fix it" for anything that isn't a PASS.

### What I found
| Run | PermitRootLogin | Result |
|---|---|---|
| Default VM | `prohibit-password` (key only) | 1 pass, 2 warn, 0 fail |
| Deliberately weakened | `yes` (password or key) | 1 pass, 1 warn, **1 fail** |
| Hardened | `no` | **2 pass**, 1 warn, 0 fail |

- The default Ubuntu settings were reasonable but not hardened: root could log in with a key, and password login was on for normal users.
- Changing one setting flipped only the matching check, which shows the script reacts correctly to real misconfigurations.
- Setting `PermitRootLogin no` blocks root from logging in over SSH at all. An attacker then has to compromise a normal account first and escalate separately, which adds a step and leaves more evidence in the logs.

### What's still open
- Password login is still a WARN. Fixing it safely requires setting up SSH keys first, or I could lock myself out.
- The sudo check passes with one admin. Each extra sudo user adds risk, and disabling root SSH makes that group matter more.
- I changed the config file only. The running SSH server picks up changes after a restart (`sudo systemctl restart ssh`).

### Limitations
- Only three checks so far, and the script audits only the machine it runs on.
- It reads global SSH settings and doesn't account for per-user `Match` overrides.
- The "more than one sudo user = WARN" rule is a heuristic, not a universal standard.
- The script is read-only: it reports problems and never changes anything.

### Next
Add checks for world-writable files, SUID binaries, `/etc/shadow` permissions, open ports, firewall status, pending updates, and failed logins.