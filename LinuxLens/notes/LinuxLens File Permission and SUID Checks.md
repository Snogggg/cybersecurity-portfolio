
## What  added
Two new checks to the read-only audit script:
1. **World-writable files and directories**
2. **Unexpected SUID binaries**

The script only **reports** these. It never changes permissions.

## Background: Linux file permissions
Every file has three permission sets, each with read (r), write (w), and execute (x):

| Who | Meaning |
|---|---|
| **Owner** | The user who owns the file |
| **Group** | Users in the file's group |
| **Others** | Everyone else on the system ("world") |

- Each permission has a number: **r=4, w=2, x=1**. They add up per set.
- `chmod 777` = owner 7 (rwx), group 7 (rwx), others 7 (rwx) = **everyone can read, write, and run it**.
- `ls -l` shows it as `-rwxrwxrwx`.
- A normal file is more like `644` (`-rw-r--r--`): owner can write, everyone else can only read.

## Check 1: World-writable files and directories
**World-writable** means the "others" set has write permission, so **any user or program** on the machine can change it.

**Why it's a risk:** if root ever runs or reads that file (a script, a config), an attacker who edited it gets root-level effects. That is a path to privilege escalation.

**Directories and the sticky bit:** some shared directories, like `/tmp`, have to be world-writable. The **sticky bit** makes it so users can only delete their own files there. So the script only warns on world-writable directories **without** the sticky bit.

**How the script finds them:**
- `find / -xdev -type f -perm -0002` lists files where the "others write" bit is set.
- `-xdev` stays on the main disk and skips virtual filesystems.
- `2>/dev/null` hides permission-denied noise.

**Fix:** `sudo chmod o-w <file>` (remove write from others).
![screenshot](../screenshots/Pasted%20image%2020261109195001.png)
## Check 2: SUID binaries
**SUID** (set user ID) is a **separate permission bit** from read/write/execute. A SUID program runs with its **owner's** privileges, usually root, no matter who launches it.

- Some are normal: `passwd` needs it so you can change your own password, which edits root-only files.
- **Risk 1:** a bug in a SUID program can become a path to root.
- **Risk 2:** an **unexpected** SUID binary is a classic place for an attacker to leave a backdoor.

**How the script works:**
- `find / -xdev -type f -perm -4000` lists every SUID file.
- It compares each name against a list of known-normal Ubuntu binaries.
- Anything not on the list gets a WARN.

**Fix:** verify it's legitimate. If not, `sudo chmod u-s <file>`.
![screenshot](../screenshots/Pasted%20image%2020261109195024.png)
## Tuning the false positives
My first full run flagged three binaries:
- `/usr/sbin/pppd` (PPP/VPN-style connections)
- `/usr/bin/ntfs-3g` (read/write Windows NTFS drives)
- `/usr/bin/sudo.ws` (alternate name for sudo)

I checked them with `dpkg -S <file>`, which shows which package owns a file. All three belong to OS packages, so they're normal, not something an attacker added. I added them to the allowlist. A file that **no** package owns would be the suspicious one.

This is how real audit tools reduce **false positives**: investigate each finding, verify, then tune.

## Testing: break it on purpose
| Step | What I did | Result |
|---|---|---|
| Baseline | Clean VM | 5 pass, 1 warn, 0 fail |
| World-writable test | `touch ~/badfile && chmod 777 ~/badfile` | WARN naming `/home/alex/badfile` |
| SUID test | Copied `cat` to `/usr/local/bin/lenstest`, then `chmod u+s` | WARN naming `/usr/local/bin/lenstest` |
| Combined run | Both planted | 3 pass, 3 warn, 0 fail |
| Cleanup | `rm ~/badfile` and `sudo rm /usr/local/bin/lenstest` | Back to 5 pass, 1 warn, 0 fail |
![screenshot](../screenshots/Pasted%20image%2020261109195039.png)
- Only the matching checks changed, so the script reacts to real problems.
- The fake SUID `cat` could read any file as root, so I removed it right after the test.
- The one remaining WARN is SSH password login, which stays until I set up SSH keys.

## Why these two checks pair well with the SSH checks
Together they cover the attack chain:
1. **Get in:** SSH password login and root login (previous checks)
2. **Escalate:** world-writable files and SUID binaries, the common routes from a normal user to root (this note)
3. **Limit the blast radius:** sudo group size

## Problems I hit
- **Syntax error after editing in nano:** I broke a quote on a long line. `bash -n linuxlens.sh` checks syntax without running the script. Re-pasting the full script fixed it.
- **First SUID run had false positives:** fixed by verifying with `dpkg -S` and tuning the list.

## Limitations
- The SUID allowlist is based on Ubuntu 26.04 and needs adjusting per distro.
- It only scans the main filesystem (`-xdev`), so other mounted disks are skipped.
- It doesn't check for SGID binaries, capabilities, or world-writable files on other mounts.
- A WARN means "investigate," not "compromised."


Part 2 

#Summary

Right here our goal was to work on least privilege configs. Here we created 2 different text files where the passwd contains usernames, and ids but no sensitive information such as passwords in here, however the other file shadow contains the hashed passwords not plaintext. Now the observation and fix we are doing here is we are wanting to make the passwd file readable to all and restrict writing in it to root users only. The reason for this is if we gave everyone the ability to write in this file they could create new user accounts and elevate that accounts privileges to root which then gives them access to shadow file. The shadow file if breached by the wrong user they can collect the hashed passwords and crack them offline on there machine, this is a major risk especially if the passwords are weak. Furthermore with root permissions they would be capable of writing in the shadow file and altering the integrity of those passwords to there own hashed passwords which makes cracking accounts easier. 


![screenshot](../screenshots/Pasted%20image%2020261111190805.png)




# LinuxLens: /etc/passwd and /etc/shadow Permission Check (Least Privilege, Part 1)

## What I added
A new read-only check, `check_auth_files`, that grades the permissions on the two most sensitive account files. It only **reports**. It never changes permissions.

## Concept: least privilege
Give each user, program, or group only the access it actually needs, and nothing more. These two files are good examples, because only a few things need to touch them.

## How Linux permissions work
Each file has three permission sets, in this order: **owner, group, others**. Each set is a sum of **r=4, w=2, x=1**.

| Digit | Made of | Meaning |
|---|---|---|
| 7 | 4+2+1 | read, write, execute |
| 6 | 4+2 | read, write |
| 5 | 4+1 | read, execute |
| 4 | 4 | read only |
| 0 | nothing | no access |

So `644` is three separate digits (6, 4, 4), not "six hundred forty-four."

Execute only matters for programs, scripts, and directories. These two are plain data files, so nobody needs execute on them.

## The two files
| File | Holds | Normal perms | Meaning |
|---|---|---|---|
| `/etc/passwd` | Account list (username, user ID, home folder). No password hashes. | `644` | Owner reads/writes. Everyone else reads only. |
| `/etc/shadow` | **Hashed passwords** | `640` | Owner reads/writes. Group reads. **Others get nothing.** |

- `/etc/passwd` must be readable by everyone, because programs use it to turn user IDs into names.
- The `shadow` group gets read because system programs that verify passwords run under it.

## Why each one matters
- **Read access to `/etc/shadow`:** an attacker copies the hashes and cracks them **offline**, with no lockouts and no logs. Weak passwords fall quickly.
- **Write access to `/etc/shadow`:** an attacker swaps in a hash for a password they chose. They log in as that user, root included, with no cracking needed.
- **Write access to `/etc/passwd`:** an attacker adds an account with **user ID 0**. Linux decides power by user ID, not by name, so that account is root. The owner and group labels no longer matter once you are root.

## How the script grades it
| Condition | Grade |
|---|---|
| `/etc/shadow` readable or writable by **others**, or owner isn't root | **FAIL** |
| `/etc/shadow` writable by its **group** | **WARN** |
| `/etc/passwd` writable by anyone but root, or owner isn't root | **FAIL** |
| Normal values (`640` / `644`) | **PASS** |

**How it reads permissions:** `stat -c '%a' file` prints the number, then the script splits it into owner, group, and others digits and checks the write and access bits with simple arithmetic.

## Results
| Run | `/etc/shadow` | Result |
|---|---|---|
| Baseline | `640 root:shadow` | `[PASS]`, 7 pass, 1 warn, 0 fail |
| **Break-it test:** `sudo chmod 644 /etc/shadow` | `644` (others can read) | `[FAIL] /etc/shadow has unsafe permissions (644, owner root)`, 6 pass, 1 warn, 1 fail |
| Restored: `sudo chmod 640 /etc/shadow` | `640 root:shadow` | `[PASS]`, back to 7 pass, 1 warn, 0 fail |

- Only the shadow line changed, so the check reacts to exactly the setting I changed.
- The 644 state exposes every password hash on the machine to every user, so I restored it right after the screenshot.
- The one remaining WARN is SSH password login, which stays until SSH keys are set up.

## Terms I learned
- **nano** = terminal text editor (Ctrl+O save, Ctrl+X exit)
- **bash** = the shell that runs my commands **and** the scripting language of `linuxlens.sh` (`bash -n file` checks syntax without running it)
- **sudo** = run one command as root, using my own password
- **hash** = a scrambled, one-way version of a password
- **offline cracking** = guessing passwords on the attacker's own machine, with no lockouts or logs

## Mistakes I hit
- Typos like `.linuxlens.sh` (missing `/`) and `linuslens.sh` (swapped letters) gave "command not found." Harmless, but check the spelling and the `./`.
- My first screenshot of the FAIL run showed the file still at 644. I confirmed the restore with `stat` and a second clean run.

## Limitations
- It checks only these two files, not `/etc/group` or `/etc/gshadow`.
- It checks permissions and the owner name, not the file's group, and not file contents (for example, an extra UID 0 account inside `/etc/passwd`).
- A FAIL means "fix this now." A clean PASS doesn't prove the files weren't already tampered with.



Break test Screenshot. where perms were set to 644. 
![screenshot](../screenshots/Pasted%20image%2020261111191619.png)