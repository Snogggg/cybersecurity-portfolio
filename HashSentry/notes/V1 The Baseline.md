

## What HashSentry is
A Python tool for **file integrity monitoring**. It records a fingerprint of every file in a folder, then later checks whether anything changed. This is the **integrity** part of the CIA triad (confidentiality, integrity, availability).

- It is a **detective** control: it notices changes after they happen.
- It is **not preventive**. It can't stop or undo a change. Preventive controls are things like file permissions and `chattr +i` (immutable).
- It only reads. It never modifies the folder it scans.
- It covers a gap from LinuxLens: there I checked `/etc/passwd` and `/etc/shadow` **permissions**, but not their **contents**. Hashing catches content changes.
- It builds on AuthWatch's audit log, which also chains SHA-256 hashes.

## The demo folder (synthetic)
`samples/demo.py make` builds `samples/demo-tree` with these files:

| File | Contents |
|---|---|
| `config.ini` | `[app]` settings, including `role=user` |
| `app.py` | a one-line demo script |
| `notes.txt` | meeting notes |
| `readme.txt` | demo description |
| `data/users.csv` | two sample users |
| `logs/app.log` | a log file (**excluded** from scanning) |

All of it is made-up data. Nothing real is at risk.

## What the baseline records for each file
Command: `python hashsentry.py baseline samples\demo-tree --db samples\baseline.json --exclude "logs"`

| Field | What it is | Why it's collected |
|---|---|---|
| **SHA-256 hash** | A fingerprint of the file's content | Changing even one character gives a totally different hash. This is the decisive check. |
| **Size** | Bytes | Quick extra detail, but easy to keep the same while changing content |
| **Permissions (mode)** | e.g. `0666` | Detects permission changes even when content is identical |
| **Modified time** | Timestamp | Informational only. An attacker can reset it. |
| **Kind** | file or symlink | Symlinks are recorded as links, not followed |

- **5 files** were recorded (`logs` was excluded).
- **Hidden files are scanned too.** Dotfiles are where attackers hide things.
- **Exclude patterns** skip noisy paths like logs and caches. Files that change constantly would drown out real findings.

## The seal (protecting the baseline)
An attacker who can edit your files can also edit your baseline, which would blind the tool. So HashSentry also writes a **seal**: a hash of the baseline file itself, saved in `baseline.json.seal`.

- On every check, it recomputes the baseline's hash and compares it to the seal.
- If they differ, it prints `BASELINE TAMPERED OR REPLACED` and **refuses to compare**.
- Setting the `HASHSENTRY_KEY` environment variable switches to **HMAC-SHA256**, which an attacker can't forge without the key.
- **Limit:** a seal stored next to the baseline only protects against accidents. Keep a copy somewhere the scanned machine can't write (another host, a password manager), or use the HMAC key.

## First check (nothing changed)
Command: `python hashsentry.py check samples\demo-tree --db samples\baseline.json`

![screenshot](../screenshots/Pasted%20image%2020261116191748.png)
The current state matches the baseline, so no findings.

## Safe re-baselining
`baseline` refuses to overwrite an existing baseline without `--force`. Re-baselining **accepts the folder's current state as normal**, so it should only happen after reviewing a check.

## Terms
- **Hash:** a one-way fingerprint of data. Same input, same hash. Different input, different hash.
- **SHA-256:** a common hashing algorithm.
- **Baseline:** the recorded known-good state.
- **HMAC:** a hash that also needs a secret key, so it can't be forged.
- **Detective vs. preventive control:** noticing a problem vs. stopping it.