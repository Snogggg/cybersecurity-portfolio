


## What this is
LinuxLens is a **read-only** audit script. It never changes the system. It reads the SSH server's settings and grades them PASS / WARN / FAIL, with a "why" and a "fix" for anything that isn't a PASS.

## SSH in one line
SSH (port 22) lets users log into a machine over a network. It stays on and open. The audit checks how it's *configured*.

## The setting: PermitRootLogin
| Value | Meaning | Grade |
|---|---|---|
| `no` | Root can't log in over SSH at all (no password, no key) | PASS (safest) |
| `prohibit-password` | Root can log in with an SSH **key** only | WARN (a stolen key = full control) |
| `yes` | Root can log in with a password or a key | FAIL (attackers can guess the password) |

- My VM's default was `prohibit-password`, so my first run showed WARN.
- The fix the script recommends is `PermitRootLogin no` in `/etc/ssh/sshd_config`. I haven't applied it yet.
- Only **root** is blocked. Normal users like `alex` can still log in over SSH.

## Why it matters
- Every Linux machine has a `root` account, so attackers already know the username. Only the password is unknown.
- With root login allowed: guess the root password or steal a key and you own the machine in one step.
- With root login disabled: the attacker must (1) compromise a normal, unprivileged account, then (2) escalate separately, through sudo or an exploit.
- Each extra step adds chances to detect and stop them, and logs show which user did what.

## Why `sshd -T` and not grep
`sshd -T` prints the settings the SSH server is **actually using**, including defaults. `grep` on the config file only finds settings someone wrote down, so it can miss defaults and included files.

## Test plan
1. Set `PermitRootLogin yes` on my lab VM on purpose.
2. Run the script and confirm the check flips from WARN to FAIL.
3. Screenshot before and after for the README.
4. Set it back to `prohibit-password`, then try `no` and confirm PASS.
![screenshot](../screenshots/Pasted%20image%2020261109190705.png)
The top finding was the VM default SSH config settings where it showed 1 pass and 2 warn meaning that the 1st pass was because only 1 account inside the sudo group meaning that IF there was an attack there is only 1 attack surface to really investigate. The 2 warns came from first the SSH root login using only key and not pass still not secure enough as keys can be stolen, and the other warn comes from default users being allowed to login via password which can be exploited via brute force attack. 


The second finding was when I adjusted the settings of the SSH config to a weaker state where SSH root login was enabled meaning password and keys are allowed which is a BIG red flag so it failed the finding, and the 1 pass came from only having one attack surface being "alex" in this case being the only user in the sudo group. Lastly the warn came from again having SSH user login tom password enabled so brute force is still a big risk here. 



![screenshot](../screenshots/Pasted%20image%2020261109192218.png)

In this case we went to the ssh config settings again and changes PermitRootLogin to no meaning that no root account can be  logged in using key or pass. 