"""
Simple File Integrity Monitor (SHA-256)

Usage:  python simple_fim.py <directory>   (or just run it and type the folder when asked)
  1st run -> creates baseline.json
  2nd run -> compares and writes integrity_report.txt + detection_rule.yml
"""
import hashlib
import json
import os
import sys
from datetime import datetime

# Folder to monitor when no input is possible (e.g. browser-based editors).
# Change this to the name of your test folder.
DEFAULT_FOLDER = "test_folder"

BASELINE = "baseline.json"
REPORT = "integrity_report.txt"
RULE = "detection_rule.yml"


def hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()


def scan(folder):
    """Return {file_path: sha256} for every file in the folder."""
    hashes = {}
    for root, _, files in os.walk(folder):
        for name in files:
            path = os.path.join(root, name)
            if name in (BASELINE, REPORT, RULE):
                continue
            try:
                hashes[path] = hash_file(path)
            except OSError:
                print("Could not read:", path)
    return hashes


def write_report(modified, new, deleted):
    with open(REPORT, "w") as f:
        f.write("INTEGRITY REPORT - " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
        f.write("=" * 50 + "\n")
        for title, items in (("MODIFIED", modified), ("NEW", new), ("DELETED", deleted)):
            f.write(f"\n{title} FILES ({len(items)})\n")
            for item in items:
                f.write("  - " + item + "\n")


def write_rule(folder, modified, new, deleted):
    """Write a simple Sigma rule that watches the changed files."""
    paths = modified + new + deleted
    with open(RULE, "w") as f:
        f.write("title: File integrity change detected\n")
        f.write("status: experimental\n")
        f.write("description: Files changed, added or deleted since baseline\n")
        f.write("logsource:\n    category: file_event\n")
        f.write("detection:\n    selection:\n        TargetFilename|contains:\n")
        for p in paths or [folder]:
            f.write(f'            - "{p}"\n')
        f.write("    condition: selection\n")
        f.write("level: high\n")


def main():
    if len(sys.argv) == 2:
        folder = sys.argv[1]
    else:
        try:
            folder = input("Enter the folder to monitor (e.g. C:\\test or ./test): ").strip().strip('"')
        except EOFError:
            folder = ""  # no keyboard input available (browser editors)
        if not folder:
            folder = DEFAULT_FOLDER
            print("Using default folder:", folder)
    if not os.path.isdir(folder):
        if folder == DEFAULT_FOLDER:
            # Create a small demo folder so the project can be tried right away
            os.makedirs(folder)
            for name, text in (("notes.txt", "hello\n"), ("config.txt", "debug=false\n")):
                with open(os.path.join(folder, name), "w") as f:
                    f.write(text)
            print("Created demo folder:", os.path.abspath(folder))
        else:
            print("Folder not found:", folder)
            print("Script is running from:", os.getcwd())
            return
    current = scan(folder)

    if not os.path.exists(BASELINE):
        with open(BASELINE, "w") as f:
            json.dump(current, f, indent=2)
        print(f"Baseline created with {len(current)} files. Run again to compare.")
        return

    with open(BASELINE) as f:
        baseline = json.load(f)

    new = sorted(current.keys() - baseline.keys())
    deleted = sorted(baseline.keys() - current.keys())
    modified = sorted(p for p in current.keys() & baseline.keys() if current[p] != baseline[p])

    write_report(modified, new, deleted)
    write_rule(folder, modified, new, deleted)
    print(f"Modified: {len(modified)} | New: {len(new)} | Deleted: {len(deleted)}")
    print(f"Created {REPORT} and {RULE}")


main()