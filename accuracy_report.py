#!/usr/bin/env python3
"""Accuracy Report — reads docs/accuracy_report.json and prints summary."""

import json
from pathlib import Path

data = json.loads(Path("docs/accuracy_report.json").read_text())
m = data["metrics"]
cm = data["confusion_matrix"]

print("=" * 60)
print("ACCURACY REPORT — FIND EVIL! Hackathon")
print("=" * 60)
print(f"Provider: {data['provider']}")
print(f"Pipeline: {data['pipeline']}")
print(f"Files: {len(data['results'])}")
print()
print(f"  Accuracy:  {m['accuracy']:.4f} ({m['accuracy']*100:.1f}%)")
print(f"  Precision: {m['precision']:.4f} ({m['precision']*100:.1f}%)")
print(f"  Recall:    {m['recall']:.4f} ({m['recall']*100:.1f}%)")
print(f"  F1 Score:  {m['f1']:.4f}")
print(f"  FPR:       {m['fpr']:.4f} ({m['fpr']*100:.1f}%)")
print()
print(f"  TP={cm['TP']}  FP={cm['FP']}  TN={cm['TN']}  FN={cm['FN']}")
print()
for r in data["results"]:
    ok = "✅" if r["outcome"] in ("TP", "TN") else "❌"
    print(f"  {ok} {r['file']:35s} | {r['gt']:8s} → {r['pred']:10s} | {r['outcome']}")
