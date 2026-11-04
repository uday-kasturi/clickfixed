#!/usr/bin/env python3
"""Turn your own shell history into extra benign rows: corpus/benign_local.csv.

The output stays on your machine (it is git-ignored). Review it before using: history can
contain secrets. Run the eval against it with:
  cfx-eval run --benign corpus/benign_local.csv
"""
import csv, os, sys

def main():
    hist = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/.bash_history")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = os.path.join(root, "corpus", "benign_local.csv")
    seen, rows = set(), []
    with open(hist, errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.startswith(": ") and ";" in line:  # zsh extended history
                line = line.split(";", 1)[1]
            if len(line) < 4 or line in seen:
                continue
            seen.add(line)
            rows.append([f"H{len(rows)+1:05d}", "shell_history", "linux", line,
                         "unknown", "terminal:bash", "engineering", "", "", "typed or recalled"])
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id","category","platform","text","origin","target","role","bypass_risk","source_row","notes"])
        w.writerows(rows)
    print(f"wrote {len(rows)} rows to {out}")

if __name__ == "__main__":
    main()
