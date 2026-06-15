#!/usr/bin/env python3
"""Regenerate docs/dataset.md from the actual corpus the accuracy report tested.

This script reads the accuracy_report.json and produces a dataset.md that
matches the numbers, instead of the stale 118-sample document.
"""
import json
from pathlib import Path

ACC = json.loads(Path("docs/accuracy_report.json").read_text())
metrics = ACC["metrics"]
per_sev = ACC["per_severity"]
per_tag = ACC.get("per_tag", {})
per_detector = ACC.get("per_detector", {})

total = metrics["total"]
tp = metrics["confusion_matrix"]["TP"]
fp = metrics["confusion_matrix"]["FP"]
tn = metrics["confusion_matrix"]["TN"]
fn = metrics["confusion_matrix"]["FN"]
mal = tp + fn
ben = tn + fp
acc = metrics["accuracy"]
prec = metrics["precision"]
rec = metrics["recall"]
f1 = metrics["f1"]
fpr = metrics["fpr"]

# Derive the benign split from what the report ACTUALLY evaluated (results array),
# not a fragile disk-walk: a hardcoded extension list silently drops .jsx and the
# extensionless Dockerfile, producing the wrong split (10+27 instead of 12+26).
import os
results = ACC.get("results", [])
benign_results = [r for r in results if str(r.get("gt", "")).upper() == "BENIGN"]
local_ben = sum(1 for r in benign_results if "benign_corpus" in str(r.get("file", "")))
lab_ben = sum(1 for r in benign_results if "benign_corpus" not in str(r.get("file", "")))
# lab_mal is the raw on-disk malicious file count (the report scans a scannable subset);
# falls back to the evaluated malicious total when the lab is not mounted.
LAB = Path(os.environ.get("CYBERSEC_LAB", "/home/gris/.hermes/workspace/cybersecurity-lab"))
_lab_mal_dir = LAB / "test-corpus" / "malicious"
lab_mal = sum(1 for f in _lab_mal_dir.iterdir() if f.is_file()) if _lab_mal_dir.exists() else mal

sev_rows = []
for sev in ["critical", "high", "medium", "none"]:
    if sev in per_sev:
        s = per_sev[sev]
        sev_rows.append(f"| {sev.capitalize()} | {s['total']} | {s['recall']*100:.0f}% ({s['detected']}/{s['total']}) |")

# Only 4 of the 8 scenario-expected detector labels have a scanner that actually
# runs; the other 4 are ground-truth labels with no backing scanner, so their 0%
# is structural, not a missed detection. Annotate this explicitly so the 0% rows
# aren't read as failures.
WIRED_DETECTORS = {"yara", "skill_scanner", "ioc_scanner", "secrets_detector"}
NOT_WIRED_NOTE = {
    "sigma": "**not wired** (scenario-labelled, no scanner in pipeline)",
    "drift": "**not wired** (no implementation)",
    "behavioral_monitor": "**not wired**",
    "suricata": "**not wired**",
}
det_items = [(n, d) for n, d in per_detector.items() if isinstance(d, dict)]
# wired scanners first (highest detection rate first), then unwired labels
det_items.sort(key=lambda kv: (kv[0] not in WIRED_DETECTORS, -kv[1].get("detection_rate", 0)))
det_rows = []
for det_name, det in det_items:
    rate = det.get("detection_rate", 0) * 100
    status = "wired" if det_name in WIRED_DETECTORS else NOT_WIRED_NOTE.get(det_name, "**not wired**")
    det_rows.append(
        f"| `{det_name}` | {det.get('actually_flagged', 0)}/{det.get('expected', 0)} | {rate:.1f}% | {status} |"
    )

tag_rows = []
for tag, t in per_tag.items():
    if isinstance(t, dict) and "recall" in t:
        tag_rows.append(f"| `{tag}` | {t.get('total', 0)} | {t.get('detected', 0)} | {t.get('recall', 0)*100:.0f}% |")

content = f"""# Dataset Documentation — MR. Robot Adversarial

## Overview

The MR. Robot Adversarial evaluation corpus consists of **{mal} adversarial malicious
scenarios** and **{ben} benign samples** ({local_ben} in this repo's `benign_corpus/` +
{lab_ben} in `cybersecurity-lab/test-corpus/benign/`), for a total of **{total} ground-truth
labelled samples** used to measure both recall and false-positive rate.

**Sources:**
- Malicious: `cybersecurity-lab/test-corpus/malicious/` (lab total: {lab_mal} files; evaluation subset: {mal} scannable)
- Benign: `benign_corpus/` (this repo, {local_ben} samples) + `cybersecurity-lab/test-corpus/benign/` ({lab_ben} samples)

**Format:** Raw source files (Python, JS, YAML, shell, etc.) — what a real IR responder would encounter
**License:** MIT (same as repository)

## Headline Metrics (from `docs/accuracy_report.json`)

| Metric | Value |
|--------|-------|
| Total samples | {total} |
| True positives (malicious correctly flagged) | {tp} |
| False positives (benign flagged) | {fp} |
| True negatives (benign correctly cleared) | {tn} |
| False negatives (malicious missed) | {fn} |
| **Accuracy** | **{acc*100:.2f}%** |
| **Precision** | **{prec*100:.2f}%** |
| **Recall** | **{rec*100:.2f}%** |
| **F1** | **{f1*100:.2f}%** |
| **FPR (False Positive Rate)** | **{fpr*100:.2f}%** ({fp}/{ben} benigns flagged) |

## Severity Distribution (per-severity recall)

| Severity | Total | Recall |
|----------|-------|--------|
{chr(10).join(sev_rows)}

## Per-Detector Performance

| Detector | Detected / Total | Recall | Status |
|----------|------------------|--------|--------|
{chr(10).join(det_rows) if det_rows else '| (no per-detector data in this report) | — | — | — |'}

> Only 4 of the 8 scenario-expected detector *labels* correspond to scanners that
> actually run (`yara`, `skill_scanner`, `ioc_scanner`, `secrets_detector`). The
> other 4 are ground-truth labels from the scenario corpus with no backing scanner
> in this pipeline — their 0% is structural, not a missed detection. Overall recall
> is still 100% because every malicious sample is caught by at least one wired scanner.

## Attack Category Distribution (per-tag recall)

| Tag | Total | Detected | Recall |
|-----|-------|----------|--------|
{chr(10).join(tag_rows) if tag_rows else '| (no per-tag data in this report) | — | — | — |'}

## The 1 False Positive

The single FP is on a benign corpus sample flagged by `secrets_detector`. Documented
in `docs/accuracy_report.json` as a known FP, with a fix in the scanner rule queued.

## Limitations — Read Before Citing

- **Self-authored corpus.** Recall=100% reflects curated corpus bias, not
  generalization to novel attacks. We document this honestly rather than claim
  SOTA performance. The public benchmark (CyberSOCEval) shows ~10% exact-match
  on a held-out, independently-authored set — see `docs/cybersoceval_results.md`.
- **No spoliation test exercised.** The falsifier was not given destructive
  permission to confirm the refusal path. The architectural argument stands
  (the LLM cannot run shell commands) but the empirical refusal test is
  not in this submission.
- **Phantom detectors.** `drift`, `behavioral`, `sigma`, `suricata` are listed
  in some docs as available scanners but are NOT wired into the orchestrator's
  `_run_scanner()` path. The 4 wired scanners are: `skill_scanner`, `ioc_scanner`,
  `scan_yara`, `secrets_detector`.

## Reproducing

```bash
# From repo root, with $CYBERSEC_LAB set to the cybersecurity-lab repo:
export CYBERSEC_LAB=/path/to/cybersecurity-lab
python generate_accuracy_report.py
# This regenerates docs/accuracy_report.json from the current corpus.
# Then re-run this script to regenerate dataset.md:
python scripts/regenerate_dataset_md.py
```

The accuracy report script takes ~3 minutes for the full 173-sample run.
"""

Path("docs/dataset.md").write_text(content)
print(f"Wrote docs/dataset.md ({Path('docs/dataset.md').stat().st_size} bytes)")
print(f"Headline: {mal} malicious + {ben} benign = {total} samples")
print(f"Per-severity: critical={per_sev.get('critical', {}).get('total', 0)}, "
      f"high={per_sev.get('high', {}).get('total', 0)}, "
      f"medium={per_sev.get('medium', {}).get('total', 0)}")
