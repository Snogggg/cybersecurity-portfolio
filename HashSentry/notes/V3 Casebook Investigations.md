

|               |                                                                      |
| ------------- | -------------------------------------------------------------------- |
| **Analyst**   | Alex                                                                 |
| **Date**      | 11/16/2026                                                           |
| **Tool**      | HashSentry v2 (adds rename/move detection)                           |
| **Data**      | Seven synthetic cases (RFC 5737 documentation IPs). No real systems. |
| **Reports**   | `samples/cases/caseNN/report.txt`                                    |
| **Diagnoses** | `diagnoses/caseNN.md`                                                |

## 1. Purpose
Show that I can read a file integrity report, reconstruct what happened, separate fact from inference, and say what the evidence cannot prove.

## 2. Method (applied to every case)
1. Read the report. Record the findings as **facts only**.
2. Build a timeline. Mark each time by **source** and **certainty**.
3. Form a hypothesis. List the evidence for it and **at least one benign alternative**.
4. Give a verdict, a confidence level, and a severity.
5. State what the report **cannot** tell me.
6. List response actions and the other tools I would check.

## 3. What changed in the tool
- **Rename/move detection:** a deleted file and an added file with identical content are paired as `MOVED OR RENAMED`, not reported as two unrelated events.
- **Casebook generator:** `samples/cases.py` builds before/after trees for seven scenarios and saves each report.
- **Control case:** `case00` has no changes, to confirm I can recognize a quiet result.

## 4. Reproduce
```
python samples/cases.py build
python samples/cases.py run
```

## 5. Quick reference: finding types
| Finding | Means | Does NOT mean |
|---|---|---|
| MODIFIED | Content hash changed | That the change was malicious |
| ADDED | Path not in the baseline | That the file is a threat |
| DELETED | In the baseline, now missing | That it was removed on purpose |
| MOVED OR RENAMED | Same content, new path | Who moved it or why |
| PERMISSIONS CHANGED | Mode differs, content identical | Who changed it |
| TOUCHED | Timestamp only (informational) | A real change. Timestamps can be reset |

## 6. About time in this tool
- The report's time is when the **check ran**.
- The real change happened **somewhere between the baseline and the check**.
- File modified times are informational and an attacker can set them.
- Any more precise time must come from another source (AuthWatch, auditd, logs, network monitoring). Label it as such.

## 7. Case index
| Case | Scenario                                 | Findings | Verdict   | Confidence | Severity | Status |
| ---- | ---------------------------------------- | -------- | --------- | ---------- | -------- | ------ |
| 00   | Control: quiet night                     | 0        | Benign    | Medium     | Info     | ☑      |
| 01   | Web app, after a security alert          | 1        | Unclear   | Low        | Medium   | ☑      |
| 02   | Public site with an uploads folder       | 1        | Unclear   | Medium     | High     | ☑      |
| 03   | Audit logs, after a 3 a.m. login flag    | 2        | Malicious | Medium     | High     | ☑      |
| 04   | Backup scripts, no change reported       | 1        | Unclear   | Medium     | High     | ☑      |
| 05   | Finance share, unusual outbound transfer | 2        | Malicious | Medium     | Critical | ☑      |
| 06   | App folder after a reported patch        | 3        | Unclear   | Low        | Medium   | ☑      |
Verdict: Malicious / Benign / Unclear. Confidence: Low / Medium / High. Severity: Info / Low / Medium / High / Critical.

---

## 8. Case write-ups

### Case 00: Control
**Context:** A small app folder, checked the morning after a quiet night.
![screenshot](../screenshots/Pasted%20image%2020261116204002.png)

**Report findings**

HashSentry compared the folder against `samples\cases\case00\baseline.json` (created 2026-11-17T01:50:47 UTC, 3 files). The seal verified OK (SHA-256, from seal file). 3 files were scanned and none were excluded. Result: clean, no changes. The report does not state when the check ran.

**Analysis**
- **Fact:** All 3 baselined files match their recorded hashes. The baseline seal is intact, so the baseline was not altered after it was created. The report shows the baseline time only, not the check time.
- **Inference:** The monitored files were most likely unchanged between the baseline and the check. This matches the scenario context of a quiet night.
- **Benign alternative:** A clean result needs no benign explanation. The one competing explanation is a change that was made and then reversed before the check ran.
- **Why a clean result still has limits:**
  - HashSentry is a snapshot. A modification followed by a restore between checks is invisible.
  - It covers only the monitored paths (3 files).
  - It reports state, not activity, so it cannot attribute any action to a person or process.
  - Time is a window (baseline to check), not a moment.

**Verdict / Confidence / Severity:** Benign / Medium / Info

**Cannot determine:** Whether a change was made and reverted before the check, whether anything outside the monitored paths changed, who accessed the folder, and exactly when the check ran.

**Response**
- Immediate: None required.
- Investigate: None required.
- Restore / re-baseline decision: Keep the current baseline. If reversal between checks is a concern, run checks more frequently or add real-time monitoring and `auditd` watch rules.

---

### Case 01: Web app after a security alert
**Context:** A web app folder on a server. Checked after a security alert.
![screenshot](../screenshots/Pasted%20image%2020261116204009.png)

**Report findings**
| Type | Path | Detail (hash, size, mode) |
|---|---|---|
| MODIFIED | webapp/config.ini | hash 7d3b0f24e6e5 -> cc6bc9720d34, size 48 -> 48 (same size) |

HashSentry compared the folder against `samples\cases\case01\baseline.json` (created 2026-11-17T01:50:47 UTC, 3 files). The seal verified OK. 3 files were scanned, none excluded. Result: 1 change detected.

**Timeline**
| Time | Event | Source | Certainty |
|---|---|---|---|
| 2026-11-17 01:50:47 UTC | Baseline taken | HashSentry | Reported |
| Between baseline and check | config.ini content changed (window only) | HashSentry | Reported (window) |
| Not stated in report | Check ran | HashSentry | Not reported |

**Analysis**
- **Facts (from the report):** One of 3 files, `webapp/config.ini`, has a different hash than the baseline. Its size is unchanged at 48 bytes. The seal is intact, so the baseline itself was not altered. The other 2 files match.
- **Inference (my reasoning):** The content of a configuration file was edited without changing its length, for example by replacing one value with another of equal length. A config file can control credentials, endpoints, or application behavior, so this is a plausible target. The same-size result could also be deliberate, to evade size-only checks, but the report cannot show intent.
- **Benign alternative:** An authorized administrator or a deployment/config-management tool changed a setting (such as a port or key rotation), or an admin made a manual edit. The security alert could also be unrelated to this change.
- **Why the size/hash detail matters:** The file stayed 48 bytes, so a size-only check would have reported nothing. The hash comparison caught a change that would otherwise be invisible.

**Verdict / Confidence / Severity:** Unclear / Low / Medium

**Indicators:**
- Content change with identical file size
- Change to a configuration file, not a log or cache
- Only one file affected, which suggests a targeted edit
- Change falls in a window that includes the time of the security alert (the alert time is not in the report)

**Cannot determine:** Who made the change, how (account, process, or remote access), the exact time, what the file said before and after, and whether anything outside the 3 monitored files changed.

**Response**
- **Immediate:** Preserve the report, baseline, seal, and a copy of the current `config.ini` before changing anything. Ask the team whether a config change was approved. If the file holds credentials or keys, treat them as potentially exposed until verified.
- **Investigate:** Compare the current file to a known-good copy (version control, backup, or deployment package) to see exactly what changed. Check file owner and modified time (informational only). Find out what triggered the security alert and when.
- **Restore / re-baseline decision:** Do not use `--force` yet. If the change was approved, re-baseline and record why. If not, restore from a known-good copy, rotate any exposed secrets, search for other changes, and then re-baseline.

**Cross-tool correlation:**
- **Security alert source:** What it flagged and when, to narrow the time window.
- **AuthWatch:** Logins to the server between baseline and check, especially from new IPs or at unusual hours.
- **auditd:** A write event on `config.ini` would give user, process, and time (the attribution HashSentry can't provide).
- **Web server and application logs:** Unusual requests or errors around the change.
- **Network monitoring:** Outbound connections that might suggest stolen credentials were used.
- **Change tickets / version control:** Whether the edit was authorized.

---

### Case 02: Public site with an uploads folder
**Context:** A public website folder. The uploads folder accepts files from visitors.

![screenshot](../screenshots/Pasted%20image%2020261116204020.png)

**Report findings**
| Type | Path | Detail |
|---|---|---|
| ADDED | site/uploads/.cache.php | Not in baseline (no hash or size shown in report) |

HashSentry compared the folder against `samples\cases\case02\baseline.json` (created 2026-11-17T01:50:47 UTC, 3 files). The seal verified OK. 4 files were scanned, none excluded. Result: 1 change detected.

**Timeline**
| Time | Event | Source | Certainty |
|---|---|---|---|
| 2026-11-17 01:50:47 UTC | Baseline taken (3 files) | HashSentry | Reported |
| Between baseline and check | `.cache.php` appeared in uploads (window only) | HashSentry | Reported (window) |
| Not stated in report | Check ran | HashSentry | Not reported |

**Analysis**
- **Facts:** The baseline held 3 files and the check scanned 4. The one difference is a new file, `site/uploads/.cache.php`. The seal is intact, so the baseline was not altered. The other 3 files match.
- **Inference:** A PHP file in a visitor-writable folder, with a hidden dot-prefixed name that imitates a cache file, fits a web shell or other uploaded script. If the server executes PHP in that folder, the file could allow remote code execution. This is a hypothesis; the report doesn't show the file's contents.
- **Benign alternative:** A CMS, plugin, or caching library wrote a runtime cache file into uploads, or a developer placed it there during maintenance.
- **Why the location of the file matters:** Uploads is the one folder outsiders can write to, so a new file there is the most likely path for attacker-supplied content. Executable file types (`.php`) don't belong in a folder meant for passive uploads.

**Verdict / Confidence / Severity:** Unclear / Medium / High

*(Unclear because contents are unknown. Severity is High because the potential impact is code execution on a public server. If inspection confirms it's a shell, the verdict becomes Malicious.)*

**Indicators:**
- Executable file type (`.php`) in an upload directory
- Hidden (dot-prefixed) filename
- Name imitates a benign cache file
- Appeared between baseline and check with no change reported

**Cannot determine:** What the file contains, who or what created it, how it got there (upload form, compromised account, plugin), the exact time, whether it was ever executed, and whether anything outside the monitored paths changed.

**Response**
- **Immediate:** Preserve the report, baseline, and seal. Copy the file for analysis without opening it in a browser or executing it. Then block access to it (disable PHP execution in uploads or take the file out of the web root) so it can't be run while you investigate.
- **Investigate:** Read the file's contents safely (text editor or `strings`, never execute). Check owner and permissions. Search uploads and the rest of the site for similar files. Review how the upload handler validates file types.
- **Restore / re-baseline decision:** Don't use `--force` yet. If the file is confirmed malicious, remove it, fix the upload restrictions, review for other changes, and then re-baseline. If it's confirmed legitimate, record why and re-baseline.

**Cross-tool correlation:**
- **Web server access logs:** A POST to the upload endpoint (creation), then GET requests to `/uploads/.cache.php` (execution). The second one is the key evidence of use.
- **auditd:** File creation event showing the process and user.
- **AuthWatch:** Admin or SFTP logins in the window.
- **Network monitoring:** Outbound connections from the web server after the file appeared.
- **WAF / upload logs:** The original upload request, source IP, and filename.
---

### Case 03: Audit logs after a 3 a.m. login flag
**Context:** Audit logs for an app, checked after AuthWatch flagged a 3 a.m. login for `alex` from a new IP (203.0.113.150). The `alex` account is unrelated to the analyst.

![screenshot](../screenshots/Pasted%20image%2020261116211510.png)


**Report findings**
| Type | Path | Detail |
|---|---|---|
| MODIFIED | audit/login.log | hash 65d03d233cb2 -> 003f9e0a23bf, size 292 -> 204 (shrank 88 bytes) |
| DELETED | audit/sudo.log | In baseline, now missing |

HashSentry compared the folder against `samples\cases\case03\baseline.json` (created 2026-11-17T01:50:47 UTC, 3 files). The seal verified OK. 2 files were scanned, none excluded. Result: 2 changes detected.

**Timeline**
| Time | Event | Source | Certainty |
|---|---|---|---|
| 2026-11-17 01:50:47 UTC | Baseline taken (3 files) | HashSentry | Reported |
| 3 a.m. (time zone to confirm) | Login for `alex` from 203.0.113.150 flagged | AuthWatch | Reported |
| Between baseline and check | login.log modified, sudo.log deleted (window only) | HashSentry | Reported (window) |
| Not stated in report | Check ran | HashSentry | Not reported |

**Analysis**
- **Facts:** `audit/login.log` has a different hash and is 88 bytes smaller. `audit/sudo.log` is missing. The seal is intact, so the baseline was not altered. AuthWatch separately flagged a 3 a.m. login for `alex` from a new IP.
- **Inference:** Content was removed from the login log, and the sudo log was deleted. Together, that is consistent with someone hiding their login and any privileged commands they ran. The report doesn't show the order of events, or that the flagged login made these changes. Whether privileges were escalated is unknown.
- **Benign alternative:** Log rotation, a cleanup job, or an admin's manual cleanup. The report shows no new rotated file in the folder, which weakens rotation but doesn't rule it out if rotated files are stored elsewhere.
- **What was removed, and what does that suggest about intent?** The two logs record who logged in and who used elevated privileges. Selectively altering exactly those is the pattern of someone trying to avoid attribution. Intent is an inference; a hash can't show it.
- **What does this do to my ability to investigate?** The primary local evidence for the flagged session is damaged or gone. I can't confirm what `alex` did from these files, so I must rebuild the story from copies and other sources.

**Verdict / Confidence / Severity:** Malicious / Medium / High

*(Confidence rises if other sources tie the edits to the flagged session. Severity is High because the evidence trail itself was targeted.)*

**Indicators:**
- Two audit logs altered in the same window
- Log shrank (content removed), not just appended
- Privileged-activity log deleted entirely
- Coincides with a flagged login from a new IP at an unusual hour
- No rotated or replacement files in the folder

**Cannot determine:** What was removed from `login.log`, what `sudo.log` contained, who made the changes, whether it was the flagged login, whether privileges were escalated, the exact time, and what else changed on the system.

**Response**
- **Immediate:** Preserve the report, baseline, and seal. Don't touch the remaining logs. Consider isolating the server and disabling or resetting the `alex` account pending verification.
- **Investigate (where else might a copy of these logs exist?):** Backups and snapshots, a central log server or SIEM, forwarded syslog, and the application's own logs. Also check shell history, `auditd`, and the server's file-system journal or recovery tools for the deleted file.
- **Restore / re-baseline decision:** Don't use `--force`. Restore the logs from a known-good backup only after copying the current state as evidence. Re-baseline only after the incident is resolved.

**Cross-tool correlation:**
- **AuthWatch:** Full session details for `alex` from 203.0.113.150: login time, duration, other accounts used from that IP.
- **auditd:** Delete and write events on both log files, with user and process.
- **Central log server / SIEM:** Offsite copies of both logs to recover what was removed.
- **Network monitoring:** Other activity from 203.0.113.150 and any outbound transfers.
- **Account owner:** Ask the real `alex` whether they logged in.

---

### Case 04: Backup scripts, no change reported
**Context:** Backup scripts on a server. Nobody reported any changes.


![screenshot](../screenshots/Pasted%20image%2020261116211518.png)

**Report findings**
| Type | Path | Detail |
|---|---|---|
| MODIFIED | scripts/backup.sh | hash 33565c7e7555 -> f59c0373a1d2, size 42 -> 80 (grew 38 bytes) |

HashSentry compared the folder against `samples\cases\case04\baseline.json` (created 2026-11-17T01:50:47 UTC, 3 files). The seal verified OK. 3 files were scanned, none excluded. Result: 1 change detected.

**Timeline**
| Time | Event | Source | Certainty |
|---|---|---|---|
| 2026-11-17 01:50:47 UTC | Baseline taken (3 files) | HashSentry | Reported |
| Between baseline and check | backup.sh content changed (window only) | HashSentry | Reported (window) |
| Not stated in report | Check ran | HashSentry | Not reported |
| Not applicable | Approved change | Team / change records | No change reported |

**Analysis**
- **Facts:** One of 3 files, `scripts/backup.sh`, has a different hash and is 38 bytes larger (42 to 80). The seal is intact, so the baseline was not altered. The other 2 files match. The report shows no time for the change itself.
- **Inference:** Content was most likely added to the script, enough for roughly one short command. Because the script runs unattended, a single added line (for example, copying data to another destination or launching a program) would execute on every run. The report can't show what was added or whether it is harmful.
- **Benign alternative:** An admin or developer made a small maintenance edit (adding a log line, a new directory, or a changed destination) without a ticket. A configuration-management tool could also have redeployed the script with a newer version.
- **What does "nobody reported any changes" tell me?** There is no approved change on record to explain this one, so it's unverified. That could mean an unlogged routine edit, a process gap, or an unauthorized change. The report can't separate these, so the next step is to ask the script's owner and check change records.
- **Why is a script that runs on a schedule a valuable target?** It executes automatically with no one watching, usually with elevated privileges and access to sensitive data and remote destinations. A change gives the attacker persistence and repeated execution without needing a new service, and the script is rarely reviewed. It can also be used to exfiltrate data or damage backups.
- **What does the timestamp (or its absence) tell me?** HashSentry reports only the window between baseline and check, not the moment of change. Timestamps on the file itself can be reset, so they wouldn't be reliable anyway. A precise time has to come from another source such as auditd or logs.

**Verdict / Confidence / Severity:** Unclear / Medium / High

*(Unclear because the contents are unknown. High severity because of what a scheduled script can do. If the added line is unexplained, the verdict becomes Malicious.)*

**Indicators:**
- Executable script modified, and the file grew
- No change request or report on record
- Script runs on a schedule, so any added code repeats automatically
- Only one file affected, which suggests a targeted edit

**Cannot determine:** What was added, who made the change, how (account, process, or remote access), the exact time, whether the modified script has already run, and whether anything outside the monitored paths changed.

**Response**
- **Immediate:** Preserve the report, baseline, seal, and a copy of the current `backup.sh`. Consider pausing the scheduled job until the change is verified. Ask the script owner or team whether they made an edit.
- **Investigate:** Compare the current script to a known-good copy (version control, backup, or deployment package) to see the exact added lines. Check what account runs the job and what it has access to. Review recent backup output and logs for unexpected destinations or errors.
- **Restore / re-baseline decision:** Don't use `--force` yet. If the change is approved, document it and re-baseline. If not, restore the known-good script, check for other changes, review what the job ran since the change, and rotate any credentials the script uses.

**Cross-tool correlation:**
- **auditd:** Write event on `backup.sh`, showing the user and process, plus the job's executions.
- **AuthWatch:** Logins or privilege use on the server between baseline and check.
- **Scheduler logs (cron or task scheduler):** Whether the job ran after the change.
- **Network monitoring:** Outbound traffic at job run times, especially to unfamiliar destinations.
- **Change tickets / version control:** Whether the edit was authorized.

---

### Case 05: Finance share, unusual outbound transfer
**Context:** A finance share. Network monitoring noticed an unusual outbound transfer to 203.0.113.45 last night.

![screenshot](../screenshots/Pasted%20image%2020261116211527.png)


**Report findings**
| Type | Path | Detail |
|---|---|---|
| MOVED OR RENAMED | finance/payroll.csv -> tmp/p.dat | Same content, new path |
| ADDED | tmp/upload.tar | Not in baseline (no hash or size shown in report) |

HashSentry compared the folder against `samples\cases\case05\baseline.json` (created 2026-11-17T01:50:47 UTC, 3 files). The seal verified OK. 4 files were scanned, none excluded. Result: 2 changes detected.

**Timeline**
| Time | Event | Source | Certainty |
|---|---|---|---|
| 2026-11-17 01:50:47 UTC | Baseline taken (3 files) | HashSentry | Reported |
| "Last night" (exact time not given) | Unusual outbound transfer to 203.0.113.45 | Network monitoring | Reported |
| Between baseline and check | payroll.csv moved and renamed; upload.tar created (window only) | HashSentry | Reported (window) |
| Not stated in report | Check ran | HashSentry | Not reported |

**Analysis**
- **Facts:** `finance/payroll.csv` is no longer at its original path. Identical content (same hash) exists at `tmp/p.dat`. A new file, `tmp/upload.tar`, is not in the baseline. The seal is intact, so the baseline was not altered. Network monitoring separately reported an unusual outbound transfer to 203.0.113.45.
- **Inference:** The payroll file was renamed to an unremarkable name and moved to a temporary folder, and an archive named `upload.tar` appeared beside it. This is consistent with data being staged for exfiltration. The transfer may have carried the archive, but the report can't show what the archive contains or that it was the file sent.
- **Benign alternative:** An administrator or scheduled job staged payroll data for a legitimate transfer (an accountant, a payroll provider, or a backup). The outbound transfer could also be unrelated to these file changes, since the timing is only "last night."
- **What does the move detection show that two separate findings would not?** A delete plus an add would look like two unrelated events. The pairing shows the file's content is unchanged: it is the same payroll data, relocated and renamed. That points to concealment or staging rather than a content edit.
- **Which file was involved, and why does that matter?** `payroll.csv` is likely to hold names, salaries, and possibly bank or ID details. It is sensitive and regulated data, so exposure would have legal and privacy consequences.
- **What did HashSentry not show, and why?** It doesn't see network traffic, so it can't show whether anything was sent or where. It also doesn't show the contents of `upload.tar` or who acted. And it sees state at the check, so anything created and deleted between checks is invisible.

**Verdict / Confidence / Severity:** Malicious / Medium / Critical

*(Confidence is Medium because the archive's contents and the link to the transfer are unconfirmed. Severity is Critical because of the potential exposure of payroll data. If the archive contains the payroll file and the transfer matches its timing, confidence becomes High.)*

**Indicators:**
- Sensitive file renamed to an obscure name (`p.dat`)
- Moved from the finance share to a temp directory
- New archive named `upload.tar` in the same location
- Independent network alert to an external IP in the same period
- Content hash unchanged, so the file was relocated rather than edited

**Cannot determine:** What `upload.tar` contains, whether it was the file transmitted, who did it, how (account, process, or remote access), the exact time, whether the original data was copied elsewhere, and whether anything outside the monitored paths changed.

**Response**
- **Immediate:** Preserve the report, baseline, and seal, plus copies of `tmp/p.dat` and `tmp/upload.tar` (don't open the archive on a production system). Consider blocking traffic to 203.0.113.45 and isolating the host. Notify the data owner and security/incident lead, since payroll data may be exposed.
- **Investigate:** List the archive's contents safely (for example `tar -tf`), and compare its hashes to `payroll.csv`. Check file owners and permissions. Find which account or process touched the file, and whether the same activity hit other shares.
- **Restore / re-baseline decision:** Don't use `--force`. Restore `payroll.csv` to its original location from a known-good copy only after evidence is preserved. Re-baseline after the incident is resolved. If data left the network, follow the organization's breach-notification process.

**Cross-tool correlation:**
- **Network monitoring:** Transfer size, start and end time, protocol, and source host, to match against the file's size and the archive.
- **auditd:** Rename and create events on both files, with user and process.
- **AuthWatch:** Logins to the file server or the finance account in the window.
- **Firewall / proxy logs:** Other connections to 203.0.113.45, before or after.
- **Finance team / change records:** Whether a transfer or move of payroll data was authorized.

---

### Case 06: App folder after a reported patch
**Context:** An app folder on a Friday afternoon. The team says a patch was deployed.


![screenshot](../screenshots/Pasted%20image%2020261116211544.png)


**Report findings**
| Type | Path | Detail |
|---|---|---|
| MODIFIED | app/CHANGELOG.txt | hash d4bfb7d46002 -> 649086aee714, size 22 -> 42 (grew 20 bytes) |
| MODIFIED | app/main.py | hash 7a6dcc5cb75b -> 7bf6aa6bfe23, size 20 -> 20 (same size) |
| MODIFIED | app/version.txt | hash b99b4c7cdf23 -> bd31e8d9cf8d, size 6 -> 6 (same size) |

HashSentry compared the folder against `samples\cases\case06\baseline.json` (created 2026-11-17T01:50:47 UTC, 4 files). The seal verified OK. 4 files were scanned, none excluded. Result: 3 changes detected. The 4th baselined file is unchanged.

**Timeline**
| Time | Event | Source | Certainty |
|---|---|---|---|
| 2026-11-17 01:50:47 UTC | Baseline taken (4 files) | HashSentry | Reported |
| Friday afternoon (exact time not given) | Patch deployed | Team report | Claimed |
| Between baseline and check | 3 files modified (window only) | HashSentry | Reported (window) |
| Not stated in report | Check ran | HashSentry | Not reported |

**Analysis**
- **Facts:** Three of 4 files changed: `CHANGELOG.txt` (grew 20 bytes), `main.py` (same size, new hash), and `version.txt` (same size, new hash). One file is unchanged. The seal is intact, so the baseline was not altered. The report shows no file contents and no time for the changes.
- **Inference:** The set of changes is consistent with a patch: a changelog entry added, the version file updated, and the application code changed. A version bump such as 1.0.0 to 1.0.1 would keep `version.txt` the same size. The report can't show that any of this is what happened.
- **Do the changes match the claimed patch? Which ones, and which don't?** `CHANGELOG.txt` and `version.txt` match well: both are what a release normally touches. `main.py` fits in principle, since patches change code, but a same-size edit to a code file is the one change I can't confirm without seeing the content.
- **Is anything here NOT explained by a patch?** Nothing is clearly unexplained, but nothing is verified either. The main gap is `main.py`: if the patch didn't intend to change that file, or the changes differ from the release, it would be unexplained. A changelog and version bump are also easy to edit to make an unauthorized change look like a patch.
- **Benign alternative:** This is the expected one: the team deployed a legitimate patch that updated the code, version, and changelog.
- **How would I verify this?** Compare the deployed files against the release package or build artifacts (hashes), review the change ticket and approval, check the CI/CD or deployment record for who deployed and when, and diff `main.py` against the tagged release in version control.

**Verdict / Confidence / Severity:** Unclear / Low / Medium

*(Leans benign because the changes fit a patch and a patch was claimed, but a claim isn't verification. This becomes Benign once the hashes match the release package. It becomes Malicious if `main.py` differs from the release.)*

**Indicators:**
- Three files changed together, matching a release pattern
- Same-size edits to a code file and a version file, which size checks would miss
- The explanation is a team claim only, with no evidence in the report
- A Friday-afternoon deployment, when oversight is often thinner (context, not evidence)

**Cannot determine:** What changed in each file, whether the changes match the released patch, who deployed it and how, the exact time, and whether anything outside the monitored paths changed.

**Response**
- **Immediate:** Preserve the report, baseline, and seal. Ask the team for the change ticket and release details. No containment is needed unless verification fails.
- **Investigate:** Compare file hashes against the release package or build output. Diff `main.py` against the tagged version in version control. Check deployment and CI logs for who ran the deployment and when.
- **Restore / re-baseline decision (when is `--force` appropriate?):** Use `--force` only after the changes are verified as the approved patch: the hashes match the release and the ticket exists. Then re-baseline and record why, including the ticket or release number. If verification fails, treat it as an incident, restore the known-good version, and search for other changes.

**Cross-tool correlation:**
- **CI/CD and deployment logs:** Who deployed, what artifact, and when.
- **Version control:** Whether the release tag matches the files on the server.
- **auditd:** Write events on the three files, with user and process.
- **AuthWatch:** Logins to the server around the claimed deployment time.
- **Change management / ticketing:** Approval and scope of the patch.

---

## 9. Limitations of HashSentry (observed in these cases)
- No attribution (who, how)
- Time is a window, not a moment
- A legitimate change and an attack look identical to a hash
- Snapshot only: a change and its reversal between scans is invisible
- Baseline needs protecting (seal stored off-machine, or HMAC)


