# HashSentry

A read-only Python file integrity monitor. It records a SHA-256 fingerprint of every file in a folder, then reports which files were **modified, added, deleted, or had their permissions changed** on a later check.

**Status:** complete (v1)

## Overview
HashSentry is a *detective* control: it notices changes but cannot prevent or undo them. A person reviews each finding. It never modifies the folder it scans.

It covers a gap from LinuxLens, which checked `/etc/passwd` and `/etc/shadow` *permissions* but not their *contents*. All demo data here is synthetic.

## What it does
- **baseline:** walks a folder and records SHA-256, size, permissions, and modified time per file (hidden files included, symlinks recorded as links, not followed).
- **check:** rescans and compares. Exit code is 0 when clean and 1 when changes are found.
- **Sealed baseline:** the baseline's own hash is stored in a `.seal` file. If it does not match, the check refuses to compare. Set `HASHSENTRY_KEY` to use HMAC-SHA256 instead of plain SHA-256.
- **Exclude patterns:** skip noisy paths such as logs (`--exclude "logs"`).
- **Safe re-baselining:** refuses to overwrite an existing baseline without `--force`, because re-baselining accepts the folder's current state as normal.

## Usage
```
python samples/demo.py make
python hashsentry.py baseline samples/demo-tree --db samples/baseline.json --exclude "logs"
python hashsentry.py check samples/demo-tree --db samples/baseline.json
python samples/demo.py tamper
python hashsentry.py check samples/demo-tree --db samples/baseline.json
```

## Validation
| Test | Result |
|---|---|
| Fresh baseline, immediate check | Clean, seal OK |
| `config.ini`: `role=user` changed to `role=root` (same size) | MODIFIED. Hash changed while size stayed 38, so a size-only check would miss it |
| Hidden file `.hidden_backdoor.sh` added | ADDED |
| `notes.txt` deleted | DELETED |
| `app.py` made read-only | PERMISSIONS CHANGED, content identical (`0666 -> 0444`) |
| `readme.txt` timestamp changed | TOUCHED, informational only, not counted |
| Change inside an excluded folder | Not reported |
| One space added to the baseline file | `BASELINE TAMPERED OR REPLACED`, no comparison made |

## Findings
- Hashes catch what size and timestamp checks miss: content can change with the same size, and an attacker can reset timestamps but not hashes.
- Hidden files are scanned, since dotfiles are where attackers hide things.
- The baseline is the weak point. An attacker who can edit files can edit the baseline, so it is sealed.

## Limitations
- **No attribution.** A hash comparison cannot say who or what made a change, only that it happened between two scans. That data comes from other sources: Linux `auditd` file watches, Wazuh file integrity monitoring, Sysmon, and auth logs. Even then it identifies an account, not a person.
- **A seal stored next to the baseline only protects against accidents.** Keep a copy elsewhere, or use `HASHSENTRY_KEY`.
- **Snapshot, not real-time.** A change and its reversal between scans is invisible.
- A legitimate update looks identical to an attack, so every finding needs human review.
- Permissions are meaningful on Linux. On Windows the mode only reflects the read-only flag, so baselines are not portable between platforms.
- Files that change constantly (logs, caches) need an exclude list.
- Reading every file is slow on large trees.

## Next steps
- Add `auditd` data to answer who changed a file
- Real-time watching and JSON output
- Compare against a package manager's known-good hashes (`debsums`)
- Correlate with AuthWatch by time: a flagged login followed by a file change