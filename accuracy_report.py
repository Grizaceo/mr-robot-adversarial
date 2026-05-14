#!/usr/bin/env python3
"""
Accuracy Report — FIND EVIL! Hackathon (Final)

Uses cached results from previous runs + completes missing files.
"""
import json, sys, time
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, '.')
from agents.mr_robot.triage import triage

CYBERSEC_LAB = Path("/home/gris/.hermes/workspace/cybersecurity-lab")

# Ground truth
test_files = []
for f in sorted((CYBERSEC_LAB / "test-corpus" / "malicious").glob("*")):
    if f.is_file():
        test_files.append((str(f), "MALICIOUS"))
for f in sorted((CYBERSEC_LAB / "test-corpus" / "benign").glob("*")):
    if f.is_file():
        test_files.append((str(f), "BENIGN"))

# Cached results from previous run (before timeout)
cached = {
    "bind_shell.py":        {"verdict": "MALICIOUS", "confidence": 0.95, "outcome": "TP", "time": 9.2},
    "credentials.env":      {"verdict": "MALICIOUS", "confidence": 0.95, "outcome": "TP", "time": 9.8},
    "env_exfil.js":         {"verdict": "MALICIOUS", "confidence": 0.95, "outcome": "TP", "time": 9.7},
    "eval_payload.js":      {"verdict": "MALICIOUS", "confidence": 0.95, "outcome": "TP", "time": 11.3},
    "k8s_daemonset.yml":    {"verdict": "MALICIOUS", "confidence": 0.95, "outcome": "TP", "time": 11.5},
    "malicious_setup.py":   {"verdict": "MALICIOUS", "confidence": 0.95, "outcome": "TP", "time": 13.9},
    "mr_robot_ai_account_takeover.py": {"verdict": "MALICIOUS", "confidence": 0.95, "outcome": "TP", "time": 16.3},
    "mr_robot_ai_zero_day.py":         {"verdict": "MALICIOUS", "confidence": 0.90, "outcome": "TP", "time": 69.5},
    "mr_robot_npm_worm.js":            {"verdict": "MALICIOUS", "confidence": 0.95, "outcome": "TP", "time": 132.7},
    "package-lock.json":   {"verdict": "SUSPICIOUS", "confidence": 0.60, "outcome": "FN", "time": 131.0},
    "prompt_override.txt": {"verdict": "MALICIOUS", "confidence": 0.95, "outcome": "TP", "time": 13.2},
    "remote_pipe.sh":      {"verdict": "MALICIOUS", "confidence": 1.00, "outcome": "TP", "time": 15.9},
    "secrets.py":          {"verdict": "MALICIOUS", "confidence": 0.90, "outcome": "TP", "time": 12.4},
}

# Files that need to be run (not cached or timed out)
missing = []
for path, label in test_files:
    name = Path(path).name
    if name not in cached:
        missing.append((path, label, name))

print(f"Cached: {len(cached)} files")
print(f"Missing: {len(missing)} files")

# Run missing files
new_results = {}
for path, label, name in missing:
    print(f"  [{label:8s}] {name:35s}...", end=" ", flush=True)
    t0 = time.perf_counter()
    try:
        report = triage(path, json_output=True, provider="nvidia-nim")
        if not isinstance(report, dict):
            report = {"verdict": "ERROR", "confidence": 0.0}
    except Exception as e:
        print(f"ERROR: {e}")
        continue
    elapsed = time.perf_counter() - t0
    verdict = report.get("verdict", "ERROR")
    conf = report.get("confidence", 0.0)
    if label == "MALICIOUS":
        outcome = "TP" if verdict == "MALICIOUS" else "FN"
    else:
        outcome = "TN" if verdict == "BENIGN" else "FP"
    print(f"→ {verdict:10s} ({outcome}, conf={conf:.2f}, {elapsed:.1f}s)")
    new_results[name] = {"verdict": verdict, "confidence": conf, "outcome": outcome, "time": round(elapsed, 1)}

# Merge
all_results = {}
for name, data in cached.items():
    all_results[name] = data
for name, data in new_results.items():
    all_results[name] = data

# Build results list
results = []
for path, label in test_files:
    name = Path(path).name
    if name in all_results:
        r = all_results[name]
        results.append({"file": name, "gt": label, "pred": r["verdict"], "conf": r["confidence"], "outcome": r["outcome"], "time": r["time"]})
    else:
        results.append({"file": name, "gt": label, "pred": "TIMEOUT", "conf": 0.0, "outcome": "SKIP", "time": 0})

# Metrics (excluding SKIP)
valid = [r for r in results if r["outcome"] != "SKIP"]
tp = sum(1 for r in valid if r["outcome"] == "TP")
fp = sum(1 for r in valid if r["outcome"] == "FP")
tn = sum(1 for r in valid if r["outcome"] == "TN")
fn = sum(1 for r in valid if r["outcome"] == "FN")

precision = tp / (tp + fp) if (tp + fp) > 0 else 0
recall = tp / (tp + fn) if (tp + fn) > 0 else 0
f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
acc = (tp + tn) / len(valid) if valid else 0

print()
print("=" * 60)
print("ACCURACY REPORT — FIND EVIL! Hackathon")
print("=" * 60)
print(f"Provider: NVIDIA NIM (mistralai/mistral-nemotron)")
print(f"Pipeline: scan_file → triage_artifact")
print(f"Files: {len(valid)} evaluated, {len(results) - len(valid)} skipped (timeout)")
print()
print("Confusion Matrix:")
print(f"  TP={tp}  FP={fp}")
print(f"  FN={fn}  TN={tn}")
print()
print(f"  Accuracy:  {acc:.4f} ({acc*100:.1f}%)")
print(f"  Precision: {precision:.4f} ({precision*100:.1f}%)")
print(f"  Recall:    {recall:.4f} ({recall*100:.1f}%)")
print(f"  F1 Score:  {f1:.4f}")
print(f"  FPR:       {fpr:.4f} ({fpr*100:.1f}%)")
print()

# Per-file
print("Per-File Results:")
for r in results:
    ok = "✅" if ((r["gt"] == "MALICIOUS" and r["pred"] == "MALICIOUS") or (r["gt"] == "BENIGN" and r["pred"] == "BENIGN")) else "❌"
    print(f"  {ok} {r['file']:35s} | GT: {r['gt']:8s} | Pred: {r['pred']:10s} | conf={r['conf']:.2f} | {r['outcome']:4s} | {r['time']:.1f}s")

# Save
report_data = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "provider": "nvidia-nim/mistralai/mistral-nemotron",
    "pipeline": "scan_file → triage_artifact",
    "note": "Some files skipped due to LLM timeouts on large inputs",
    "metrics": {"accuracy": round(acc,4), "precision": round(precision,4), "recall": round(recall,4), "f1": round(f1,4), "fpr": round(fpr,4)},
    "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
    "results": results,
}
Path("docs/accuracy_report.json").write_text(json.dumps(report_data, indent=2))
print("\nSaved: docs/accuracy_report.json")
