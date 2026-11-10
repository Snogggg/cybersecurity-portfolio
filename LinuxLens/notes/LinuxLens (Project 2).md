

**What it is:** a Bash script that audits a Linux machine's security settings and writes a report. It is **read-only**: it reports problems and never changes anything. It only audits the machine it runs on.

## Setup I did
- VirtualBox + Ubuntu 26.04 LTS VM (`ubuntu-lab`), 4 GB RAM, 40 GB disk
- Updated with `sudo apt update` then `sudo apt upgrade -y`
- Project folder: `~/LinuxLens`, script: `linuxlens.sh`

## Key terms
- **root** = the all-powerful admin account
- **sudo** = lets a normal user run a command with root's power
- **sudo group** = users allowed to use sudo. Fewer members = smaller attack surface
- **SSH** = remote login to a machine
- **PASS / WARN / FAIL** = how the report grades each check


![[Pasted image 20261109183438.png]]

![[Pasted image 20261109183450.png]]

![[Pasted image 20261109183513.png]]
## What the script checks (so far)
| Check                                         | Why it matters                                                                       |
| --------------------------------------------- | ------------------------------------------------------------------------------------ |
| SSH root login (`PermitRootLogin`)            | If root can log in remotely, attackers can target the most powerful account directly |
| SSH password login (`PasswordAuthentication`) | Passwords can be guessed or brute-forced. Keys are much harder to attack             |
| Sudo group members                            | Every sudo user is a path to full control if their password is stolen                |

## My first result
- Root login: **WARN** (Ubuntu default is `prohibit-password`, so keys only)
- Password login: **WARN** (Ubuntu default)
- Sudo group: **PASS** (only `alex`)
- Summary: 1 pass, 2 warn, 0 fail

## How the script works
- `#!/usr/bin/env bash` on line 1 tells Linux to run it with bash
- `id -u` returns 0 only for root, so the script refuses to run without sudo
- `sshd -T` prints the SSH server's effective settings, which the script reads
- `report()` is one function that prints and saves each result
- `tee -a` shows output on screen and appends it to `linuxlens-report.txt`

## Mistakes I hit and fixed
- `cd ~LinuxLens` failed. It needs a slash: `cd ~/LinuxLens`
- Missing `#!` line made sudo run it with plain `sh`, which gave an "Illegal number" error
- `sudo reboot` was blocked by a logged-in session. Use the power menu or `sudo systemctl reboot -i`
- VM clipboard sharing didn't work. Workaround: open Claude in Firefox inside the VM and copy from there

## Next steps
- Break the VM on purpose (enable root SSH login), confirm the script shows FAIL, screenshot before and after
- Undo the change
- Install git in the VM and commit LinuxLens to the portfolio repo
- Add more checks: file permissions (world-writable files, `/etc/shadow`), open ports, firewall, updates, failed logins