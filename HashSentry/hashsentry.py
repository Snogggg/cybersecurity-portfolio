#!/usr/bin/env python3
"""HashSentry: file integrity monitoring.

baseline  : record SHA-256, size, permissions and mtime of every file in a folder
check     : rescan and report ADDED / DELETED / MODIFIED / PERMISSIONS CHANGED files
It is a DETECTIVE control: it reports changes, it cannot prevent them.
It never modifies the folder it scans.

The baseline is sealed (SHA-256, or HMAC-SHA256 if HASHSENTRY_KEY is set), because
an attacker who can edit files can also edit the baseline.
"""

import argparse
import fnmatch
import hashlib
import hmac
import json
import os
import stat
import sys
from datetime import datetime, timezone

SCHEMA = 1


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def excluded(rel, patterns):
    # Patterns match the relative path or just the file name: "*.log", "logs/*", "cache"
    name = rel.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(name, p) for p in patterns)


def record(full):
    st = os.lstat(full)  # lstat: do not follow symlinks
    if stat.S_ISLNK(st.st_mode):
        target = os.readlink(full)
        digest = hashlib.sha256(target.encode("utf-8", "surrogateescape")).hexdigest()
        kind = "symlink"
    else:
        digest = sha256_file(full)
        kind = "file"
    return {"kind": kind, "sha256": digest, "size": st.st_size,
            "mode": f"{stat.S_IMODE(st.st_mode):04o}", "mtime": int(st.st_mtime)}


def scan(root, patterns, skip):
    root = os.path.abspath(root)
    files, errors = {}, []

    def rel_of(full):
        return os.path.relpath(full, root).replace(os.sep, "/")

    def add(full):
        rel = rel_of(full)
        if os.path.abspath(full) in skip or excluded(rel, patterns):
            return
        try:
            files[rel] = record(full)
        except OSError as e:
            errors.append(f"{rel}: {e.strerror or e}")

    for dirpath, dirnames, filenames in os.walk(
            root, followlinks=False,
            onerror=lambda e: errors.append(f"{e.filename}: {e.strerror}")):
        keep = []
        for d in sorted(dirnames):
            full = os.path.join(dirpath, d)
            rel = rel_of(full)
            if excluded(rel, patterns) or excluded(rel + "/x", patterns):
                continue
            if os.path.islink(full):
                add(full)          # a symlinked folder is tracked as a link, not walked
            else:
                keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            add(os.path.join(dirpath, name))
    return files, errors


# ---- sealing the baseline -------------------------------------------------
def seal_for(data, algo):
    if algo == "hmac-sha256":
        key = os.environ.get("HASHSENTRY_KEY")
        return hmac.new(key.encode(), data, hashlib.sha256).hexdigest() if key else None
    if algo == "sha256":
        return hashlib.sha256(data).hexdigest()
    return ""


def new_seal(data):
    algo = "hmac-sha256" if os.environ.get("HASHSENTRY_KEY") else "sha256"
    return f"{algo}:{seal_for(data, algo)}"


def verify_seal(data, expected):
    algo, _, want = expected.strip().partition(":")
    got = seal_for(data, algo)
    if got is None:
        return "NOKEY"
    return "OK" if got and hmac.compare_digest(got, want) else "MISMATCH"


def write_private(path, data):
    with open(path, "wb") as f:
        f.write(data)
    if os.name != "nt":
        os.chmod(path, 0o600)


# ---- commands --------------------------------------------------------------
def cmd_baseline(args):
    db = args.db
    seal_path = args.seal or db + ".seal"
    if os.path.exists(db) and not args.force:
        print(f"{db} already exists. Re-baselining blesses the CURRENT state of the folder, so "
              "only do it after reviewing a check. Use --force to overwrite.")
        return 2
    patterns = args.exclude or []
    files, errors = scan(args.dir, patterns, {os.path.abspath(db), os.path.abspath(seal_path)})
    doc = {"schema": SCHEMA, "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "root": os.path.abspath(args.dir), "exclude": patterns, "files": files}
    data = (json.dumps(doc, indent=1, sort_keys=True) + "\n").encode("utf-8")
    write_private(db, data)
    seal = new_seal(data)
    write_private(seal_path, (seal + "\n").encode("utf-8"))
    print(f"Baseline written: {len(files)} file(s) -> {db}")
    print(f"Seal ({seal.split(':')[0]}): {seal.split(':')[1]}")
    print(f"Seal file: {seal_path}")
    print("Store a copy of the seal somewhere the scanned machine cannot write "
          "(another host, a printout, a password manager). A seal next to the baseline "
          "only protects against accidents.")
    for e in errors:
        print(f"warning: could not read {e}")
    return 0


def cmd_check(args):
    db = args.db
    seal_path = args.seal or db + ".seal"
    if not os.path.exists(db):
        print(f"No baseline at {db}. Run the baseline command first.")
        return 2
    with open(db, "rb") as f:
        data = f.read()

    expected, source = None, ""
    if args.expect_hash:
        expected, source = args.expect_hash, "--expect-hash"
    elif os.path.exists(seal_path):
        with open(seal_path, encoding="utf-8") as f:
            expected, source = f.read(), "seal file"
    if expected is None:
        seal_line = "NOT CHECKED: no seal found, so the baseline itself is unverified"
    else:
        status = verify_seal(data, expected)
        if status == "MISMATCH":
            print("BASELINE TAMPERED OR REPLACED: it does not match its seal "
                  f"(from {source}). Results would not be trustworthy, so no comparison was made.")
            return 2
        if status == "NOKEY":
            print("The baseline is HMAC-sealed. Set the HASHSENTRY_KEY environment variable to verify it.")
            return 2
        seal_line = f"OK ({expected.split(':')[0]}, from {source})"

    doc = json.loads(data)
    old = doc["files"]
    patterns = list(doc.get("exclude", [])) + (args.exclude or [])
    new, errors = scan(args.dir, patterns, {os.path.abspath(db), os.path.abspath(seal_path)})

    added = sorted(set(new) - set(old))
    deleted = sorted(set(old) - set(new))
    modified, perms, touched = [], [], []
    for p in sorted(set(old) & set(new)):
        o, n = old[p], new[p]
        if o["sha256"] != n["sha256"] or o["kind"] != n["kind"]:
            note = f"hash {o['sha256'][:12]} -> {n['sha256'][:12]}, size {o['size']} -> {n['size']}"
            if o["size"] == n["size"]:
                note += " (same size: a size-only check would miss this)"
            if o["mode"] != n["mode"]:
                note += f", mode {o['mode']} -> {n['mode']}"
            modified.append((p, note))
        elif o["mode"] != n["mode"]:
            perms.append((p, f"{o['mode']} -> {n['mode']}"))
        elif o["mtime"] != n["mtime"]:
            touched.append(p)

    changes = len(added) + len(deleted) + len(modified) + len(perms)
    out = ["HashSentry check", "=" * 70,
           f"Baseline: {db} (created {doc['created']}, {len(old)} file(s))",
           f"Seal: {seal_line}",
           f"Scanned: {len(new)} file(s)   Excluded: {', '.join(patterns) or '(none)'}"]
    if os.path.abspath(args.dir) != doc.get("root"):
        out.append(f"NOTE: baseline was taken on {doc.get('root')}, checking {os.path.abspath(args.dir)}")
    out += [f"RESULT: {changes} change(s) detected" if changes else "RESULT: clean, no changes", ""]

    def section(title, rows):
        if rows:
            out.append(title)
            out.extend(f"  {r}" for r in rows)
            out.append("")

    section("MODIFIED (content changed)", [f"{p}   {note}" for p, note in modified])
    section("ADDED (not in baseline)", added)
    section("DELETED (in baseline, now missing)", deleted)
    section("PERMISSIONS CHANGED (content identical)", [f"{p}   {note}" for p, note in perms])
    section("TOUCHED (timestamp only, content identical; informational)", touched)
    section("COULD NOT READ", errors)
    report = "\n".join(out)
    print(report)
    if args.out:
        write_private(args.out, (report + "\n").encode("utf-8"))
    return 1 if changes else 0


def main():
    ap = argparse.ArgumentParser(description="HashSentry: file integrity monitoring")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("baseline", cmd_baseline), ("check", cmd_check)):
        p = sub.add_parser(name)
        p.add_argument("dir")
        p.add_argument("--db", required=True, help="baseline JSON file")
        p.add_argument("--seal", help="seal file (default: DB.seal)")
        p.add_argument("--exclude", action="append", help="pattern to skip, repeatable")
        if name == "baseline":
            p.add_argument("--force", action="store_true", help="overwrite an existing baseline")
        else:
            p.add_argument("--expect-hash", help="seal value stored somewhere else")
            p.add_argument("--out", help="also save the report")
        p.set_defaults(fn=fn)
    args = ap.parse_args()
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()