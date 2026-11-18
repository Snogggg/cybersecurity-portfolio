

## The tampering (simulated)
Command: `python samples\demo.py tamper`

The changes to `demo-tree` were **real**, but the files are synthetic stand-ins. Nothing important was touched. HashSentry's `check` only reads, so it changed nothing.

| # | Change made | What it stands in for |
|---|---|---|
| 1 | `config.ini`: `role=user` changed to `role=root` (same file size) | Privilege escalation through a config edit |
| 2 | `.hidden_backdoor.sh` added | A planted malicious script, hidden as a dotfile |
| 3 | `notes.txt` deleted | Removed data or evidence |
| 4 | `app.py` made read-only | A permission change (content untouched) |
| 5 | `readme.txt` timestamp changed | Timestamp-only change (content untouched) |
| 6 | `logs/app.log` appended to | A change inside an **excluded** folder |

## What the check found
Command: `python hashsentry.py check samples\demo-tree --db samples\baseline.json`

![screenshot](../screenshots/Pasted%20image%2020261116191819.png)

| Finding | Counted? | What it tells me |
|---|---|---|
| **MODIFIED** `config.ini` | Yes | The hash changed but the **size stayed 38**. A size-only check would miss this. |
| **ADDED** `.hidden_backdoor.sh` | Yes | A file not in the baseline. Hidden files are scanned. |
| **DELETED** `notes.txt` | Yes | In the baseline, now missing. |
| **PERMISSIONS CHANGED** `app.py` | Yes | Content identical (same hash), only the mode differs (`0666 -> 0444`, the Windows read-only flag). |
| **TOUCHED** `readme.txt` | **No** | Timestamp only. An attacker can reset timestamps, but not hashes, so the hash decides. |
| `logs/app.log` change | Not shown | The folder is excluded. |

Key points:
- **Hashes track content. Permissions and timestamps are tracked separately.** A permission change does not change the hash.
- **4 changes** are counted: modified, added, deleted, permissions.
- On Windows, the mode only reflects the read-only flag. On Linux it shows the full permission bits.

## Seal test (the baseline itself)
I added one space to `baseline.json`, then ran a check:

![screenshot](../screenshots/Pasted%20image%2020261116191920.png)
The tool refused to trust an edited baseline. I then rebuilt it with `--force` (`Seal (sha256): ...`), and the next check said `clean`. That blessed the tampered demo tree as the new normal, which is exactly what `--force` does.

## What I do with the findings
HashSentry reports, and a human decides. It never auto-fixes, because a legitimate update and an attack look identical to a hash, and auto-reverting could undo an approved change or destroy evidence.

| Finding | Questions to ask |
|---|---|
| MODIFIED | Was this an approved change? If not, who changed it and how? |
| ADDED | Legitimate new file, or planted? |
| DELETED | Removed on purpose? |
| PERMISSIONS CHANGED | Who changed it, and why? |

- **Approved change:** re-baseline with `--force`.
- **Unapproved change:** treat it as an incident. Investigate how it happened, restore from a known-good copy, and find what else was touched.

## The limit: no "who"
A hash comparison only sees two states, before and after. It has no idea who or what made the change, and the change could have happened any time between two scans.

| Source | What it adds |
|---|---|
| Linux `auditd` file watch (`-w /etc/passwd -p wa`) | User ID, process, and exact time of each write |
| Wazuh file integrity monitoring | Hash checks plus who-data |
| Sysmon (Windows) | Which process created or modified a file |
| Auth and `sudo` logs | Who was logged in and ran privileged commands |

Even then it identifies an **account**, not a **person**. A stolen credential looks like the real user.

## HashSentry vs. AuthWatch
| | AuthWatch | HashSentry |
|---|---|---|
| **Sees** | Login attempts (events) | File state (before vs. after) |
| **Tells me** | Who tried, from where, and whether it worked | Exactly what changed |
| **Doesn't tell me** | What the attacker did once inside | Who made the change or how |

- AuthWatch = the **entry**. HashSentry = the **effect**.
- Correlate by time. Example: AuthWatch flags `alex` logging in from a new IP at 03:12, then HashSentry shows `config.ini` modified at 04:00. The timestamps tie the entry to the effect. A SIEM automates that.


## Limitations
- No attribution (who or how).
- A seal next to the baseline only protects against accidents.
- Snapshot, not real-time. A change and its reversal between scans is invisible.
- A legitimate update looks like an attack, so every finding needs review.
- Baselines aren't portable between Windows and Linux (modes differ).
- Reading every file is slow on big trees.

## Next
- Add `auditd` data for attribution
- Real-time watching and JSON output
- Compare against package-manager hashes (`debsums`)
- Correlate with AuthWatch by time