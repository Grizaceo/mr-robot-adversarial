#!/usr/bin/env python3
"""Quick accuracy test — 3 files only."""
import json, sys, time
sys.path.insert(0, '.')
from triage_falsifier import run_self_correction_loop
from pathlib import Path

CYBERSEC_LAB = Path("/home/gris/.hermes/workspace/cybersecurity-lab")

test_files = [
    ("bind_shell.py",    f"{CYBERSEC_LAB}/test-corpus/malicious/bind_shell.py",    "MALICIOUS"),
    ("safe_app.py",      f"{CYBERSEC_LAB}/test-corpus/benign/safe_app.py",          "BENIGN"),
    ("reverse_shell.sh", f"{CYBERSEC_LAB}/test-corpus/malicious/reverse_shell.sh", "MALICIOUS"),
]

results = []
for name, path, expected in test_files:
    print(f"[{expected}] {name}...", end=" ", flush=True)
    start = time.perf_counter()
    report = run_self_correction_loop(path, confidence_threshold=0.7, max_iterations=2)
    elapsed = time.perf_counter() - start
    verdict = report.get("verdict", "ERROR")
    conf = report.get("confidence", 0.0)
    iters = report.get("_correction", {}).get("iterations", 0)
    match = "✅" if verdict == expected else "❌"
    print(f"→ {verdict} {match} (conf={conf}, {elapsed:.1f}s, {iters} iter)")
    results.append({"file": name, "expected": expected, "verdict": verdict, "match": verdict == expected})

correct = sum(1 for r in results if r["match"])
print(f"\nQuick test: {correct}/{len(results)} correct")
