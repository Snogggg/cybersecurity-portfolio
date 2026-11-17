"""Build and tamper with a SYNTHETIC demo folder for HashSentry.
  python samples/demo.py make     (create a clean demo-tree)
  python samples/demo.py tamper   (apply six changes)"""

import os
import shutil
import stat
import sys
import time
from pathlib import Path

TREE = Path(__file__).with_name("demo-tree")


def w(rel, text):
    p = TREE / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def make():
    if TREE.exists():
        shutil.rmtree(TREE, onexc=lambda fn, path, exc: (os.chmod(path, stat.S_IWRITE), fn(path)))
    w("config.ini", "[app]\nname=demo\nrole=user\ndebug=false\n")
    w("app.py", "print('hello from the demo app')\n")
    w("notes.txt", "meeting notes: rotate keys on friday\n")
    w("readme.txt", "Demo tree for HashSentry. Synthetic.\n")
    w("data/users.csv", "id,name\n1,alex\n2,sam\n")
    w("logs/app.log", "started\n")
    print(f"created {TREE}")


def tamper():
    if not TREE.exists():
        sys.exit("run 'python samples\\demo.py make' first")
    cfg = TREE / "config.ini"
    cfg.write_bytes(cfg.read_bytes().replace(b"role=user", b"role=root"))     # same size
    print("1. config.ini: role=user -> role=root (same file size)")
    w(".hidden_backdoor.sh", "#!/bin/sh\necho demo only\n")
    print("2. added .hidden_backdoor.sh")
    (TREE / "notes.txt").unlink()
    print("3. deleted notes.txt")
    os.chmod(TREE / "app.py", stat.S_IREAD)
    print("4. app.py: made read-only (content unchanged)")
    r = TREE / "readme.txt"
    t = r.stat().st_mtime + 3600
    os.utime(r, (t, t))
    print("5. readme.txt: timestamp changed only")
    with (TREE / "logs" / "app.log").open("a", newline="\n") as f:
        f.write("more log lines\n")
    print("6. logs/app.log: appended (this folder is excluded, so it should NOT show up)")


if __name__ == "__main__":
    {"make": make, "tamper": tamper}.get(sys.argv[1] if len(sys.argv) > 1 else "", lambda: sys.exit(__doc__))()