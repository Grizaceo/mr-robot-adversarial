#!/usr/bin/env python3
"""Accuracy Report — reads docs/accuracy_report.json and prints a summary.

Reconstructed to match the actual JSON schema (nested under .metrics,
per_severity, per_tag, per_detector, results with 173 entries).
The previous version crashed with KeyError because it expected a flat
schema (data["confusion_matrix"], data["provider"]) that the JSON
no longer has.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

JSON_PATH = Path("docs/accuracy_report.json")


def main() -> int:
    if not JSON_PATH.exists():
        print(f"ERROR: {JSON_PATH} not found. Run generate_accuracy_report.py first.")
        return 1
    data = json.loads(JSON_PATH.read_text())
    m = data.get("metrics", {})
    cm = m.get("confusion_matrix", {})
    per_sev = data.get("per_severity", {})
    per_det = data.get("per_detector", {})
    per_tag = data.get("per_tag", {})
    results = data.get("results", [])

    print("=" * 60)
    print("ACCURACY REPORT — MR. Robot Adversarial")
    print("=" * 60)
    print(f"Generated:        {data.get('generated_at', '?')}")
    print(f"Duration:         {data.get('duration_seconds', '?')}s")
    print(f"Pipeline:         {data.get('pipeline', '?')}")
    print(f"Files evaluated:  {len(results)}")
    print()
    if m:
        print(f"  Accuracy:  {m.get('accuracy', 0):.4f} ({m.get('accuracy', 0)*100:.2f}%)")
        print(f"  Precision: {m.get('precision', 0):.4f} ({m.get('precision', 0)*100:.2f}%)")
        print(f"  Recall:    {m.get('recall', 0):.4f} ({m.get('recall', 0)*100:.2f}%)")
        print(f"  F1 Score:  {m.get('f1', 0):.4f}")
        print(f"  FPR:       {m.get('fpr', 0):.4f} ({m.get('fpr', 0)*100:.2f}%)")
        print(f"  Total:     {m.get('total', len(results))}")
    print()
    if cm:
        print(f"  TP={cm.get('TP', 0)}  FP={cm.get('FP', 0)}  "
              f"TN={cm.get('TN', 0)}  FN={cm.get('FN', 0)}")
        print()

    if per_sev:
        print("Per-Severity Recall:")
        for sev in ("critical", "high", "medium", "none"):
            s = per_sev.get(sev)
            if not s:
                continue
            print(f"  {sev:8s}  total={s.get('total', 0):3d}  "
                  f"detected={s.get('detected', 0):3d}  "
                  f"recall={s.get('recall', 0)*100:5.1f}%")
        print()

    if per_det:
        print("Per-Detector Recall:")
        for name, det in per_det.items():
            if not isinstance(det, dict):
                continue
            # Per-detector schema is {expected, actually_flagged, detection_rate}.
            # The scanner-only runner tags files with `expected_detectors`, so
            # "expected" is the count of files that required this detector.
            print(f"  {name:24s}  expected={det.get('expected', 0):3d}  "
                  f"flagged={det.get('actually_flagged', 0):3d}  "
                  f"rate={det.get('detection_rate', 0)*100:5.1f}%")
        print()

    # False positives (the one we know about)
    fps = [r for r in results if r.get("outcome") == "FP"]
    if fps:
        print(f"False Positives ({len(fps)}):")
        for r in fps:
            print(f"  {r.get('file', '?')}")
            print(f"    flagged by: {r.get('detectors_flagged', [])}")
            print(f"    reason: {r.get('fp_reason', '?')}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
