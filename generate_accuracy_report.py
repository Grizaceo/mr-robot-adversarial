#!/usr/bin/env python3
"""
Generate Accuracy Report — MR. Robot Adversarial
=================================================

Compares scanner predictions against ground truth from scenario JSONs.

For each scenario:
- Ground truth: severity (critical/high/medium/low) + expected_detectors
- Prediction: scanner results (which scanners detected it)
- Outcome: TP (detected malicious), FP (false alarm on benign),
           TN (correctly ignored benign), FN (missed malicious)

Usage:
    python generate_accuracy_report.py --output docs/accuracy_report.json
    python generate_accuracy_report.py --verbose
"""

import json
import os
import sys
import time
import argparse
from pathlib import Path
from collections import defaultdict

# ── Paths ──────────────────────────────────────────────────────────────────────

LAB_ROOT = Path(os.environ.get("CYBERSEC_LAB",
                str(Path.home() / ".hermes" / "workspace" / "cybersecurity-lab")))
SCENARIOS_DIR = LAB_ROOT / "scenarios"
TEST_CORPUS = Path(os.environ.get("TEST_CORPUS_OVERRIDE",
                   str(LAB_ROOT / "test-corpus")))
REPO_ROOT = Path(__file__).parent.resolve()
# Benign sources (in priority order). Files listed below are treated as ground-truth BENIGN.
BENIGN_DIRS = [
    REPO_ROOT / "benign_corpus",
    TEST_CORPUS / "benign",
]
# Files we never treat as standalone samples (READMEs, schemas, etc.)
BENIGN_SKIP_NAMES = {"README.md", "_schema.json"}

# ── Helpers ────────────────────────────────────────────────────────────────────

def load_scenarios():
    """Load all valid scenario JSONs."""
    scenarios = []
    for path in sorted(SCENARIOS_DIR.glob("*.json")):
        if path.name.startswith("_"):
            continue
        try:
            doc = json.loads(path.read_text())
            if "name" in doc and "payload" in doc:
                scenarios.append(doc)
        except json.JSONDecodeError:
            continue
    return scenarios


def ensure_test_files(scenarios):
    """Generate test files for scenarios that don't have them."""
    mapping = {}
    for s in scenarios:
        filename = s.get("filename", "")
        if not filename:
            continue
        for subdir in ("malicious", "benign"):
            candidate = TEST_CORPUS / subdir / filename
            if candidate.exists():
                mapping[s["name"]] = candidate
                break
        else:
            out_dir = TEST_CORPUS / "malicious"
            out_path = out_dir / filename
            out_path.parent.mkdir(parents=True, exist_ok=True)
            payload = s.get("payload", "")
            if isinstance(payload, str) and payload.strip().startswith("```"):
                # Extract code from markdown fence
                lines = payload.strip().split("\n")
                # Remove first line (```yaml, ```python, etc.) and last line (```)
                code_lines = lines[1:] if lines[0].startswith("```") else lines
                if code_lines and code_lines[-1].strip() == "```":
                    code_lines = code_lines[:-1]
                payload = "\n".join(code_lines)
            out_path.write_text(payload)
            mapping[s["name"]] = out_path
    return mapping


def load_benign_samples():
    """Collect benign code samples from configured directories."""
    samples = []
    seen = set()
    for d in BENIGN_DIRS:
        if not d.exists():
            continue
        for path in sorted(d.iterdir()):
            if not path.is_file():
                continue
            if path.name in BENIGN_SKIP_NAMES or path.name.startswith("."):
                continue
            # Avoid duplicate filenames coming from different sources.
            if path.name in seen:
                continue
            seen.add(path.name)
            samples.append({
                "name": f"benign-{path.stem}",
                "filename": path.name,
                "filepath": path,
                "severity": "none",
                "tags": ["benign"],
                "expected_detectors": [],
            })
    return samples


def run_scanners(filepath):
    """Run all scanners on a file."""
    try:
        from mcp_tools import run_all_scanners
        return run_all_scanners(str(filepath))
    except Exception:
        return {}


def compute_ground_truth(scenario):
    """
    Determine ground truth label.
    All scenarios in the adversarial set are MALICIOUS by definition.
    Severity determines the weight.
    """
    severity = scenario.get("severity", "medium")
    # All adversarial scenarios are malicious
    return {
        "label": "MALICIOUS",
        "severity": severity,
        "expected_detectors": scenario.get("expected_detectors", []),
        "attack_techniques": scenario.get("attack_techniques", []),
        "tags": scenario.get("tags", []),
    }


def compute_prediction(scanner_results):
    """
    Determine prediction from scanner results.
    Returns MALICIOUS if any scanner flagged, BENIGN otherwise.
    """
    total_findings = 0
    detectors_flagged = []
    for scanner_name, result in scanner_results.items():
        if isinstance(result, dict):
            findings = result.get("findings", [])
            if isinstance(findings, list) and len(findings) > 0:
                total_findings += len(findings)
                detectors_flagged.append(scanner_name)

    label = "MALICIOUS" if total_findings > 0 else "BENIGN"
    return {
        "label": label,
        "total_findings": total_findings,
        "detectors_flagged": detectors_flagged,
    }


def classify_outcome(gt, pred):
    """
    Classify as TP, FP, TN, FN.
    - TP: malicious correctly flagged
    - FN: malicious missed
    - TN: benign correctly ignored
    - FP: benign incorrectly flagged
    """
    if gt["label"] == "MALICIOUS" and pred["label"] == "MALICIOUS":
        return "TP"
    elif gt["label"] == "MALICIOUS" and pred["label"] == "BENIGN":
        return "FN"
    elif gt["label"] == "BENIGN" and pred["label"] == "BENIGN":
        return "TN"
    elif gt["label"] == "BENIGN" and pred["label"] == "MALICIOUS":
        return "FP"
    return "UNKNOWN"


def compute_metrics(outcomes):
    """Compute accuracy, precision, recall, F1, FPR."""
    tp = outcomes.count("TP")
    fp = outcomes.count("FP")
    tn = outcomes.count("TN")
    fn = outcomes.count("FN")
    total = tp + fp + tn + fn

    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
        "total": total,
    }


def compute_per_severity(results):
    """Breakdown by severity level."""
    by_sev = defaultdict(lambda: {"TP": 0, "FN": 0, "total": 0})
    for r in results:
        sev = r["ground_truth"]["severity"]
        by_sev[sev]["total"] += 1
        if r["outcome"] == "TP":
            by_sev[sev]["TP"] += 1
        elif r["outcome"] == "FN":
            by_sev[sev]["FN"] += 1

    breakdown = {}
    for sev, counts in sorted(by_sev.items()):
        recall = counts["TP"] / counts["total"] if counts["total"] > 0 else 0
        breakdown[sev] = {
            "total": counts["total"],
            "detected": counts["TP"],
            "missed": counts["FN"],
            "recall": round(recall, 4),
        }
    return breakdown


def compute_per_detector(results):
    """Breakdown by expected detector."""
    by_det = defaultdict(lambda: {"expected": 0, "actually_flagged": 0})
    for r in results:
        expected = r["ground_truth"]["expected_detectors"]
        flagged = r["prediction"]["detectors_flagged"]
        for det in expected:
            by_det[det]["expected"] += 1
            if det in flagged:
                by_det[det]["actually_flagged"] += 1

    breakdown = {}
    for det, counts in sorted(by_det.items()):
        rate = counts["actually_flagged"] / counts["expected"] if counts["expected"] > 0 else 0
        breakdown[det] = {
            "expected": counts["expected"],
            "actually_flagged": counts["actually_flagged"],
            "detection_rate": round(rate, 4),
        }
    return breakdown


def compute_per_tag(results):
    """Breakdown by attack tag."""
    by_tag = defaultdict(lambda: {"total": 0, "TP": 0, "FN": 0})
    for r in results:
        for tag in r["ground_truth"].get("tags", []):
            by_tag[tag]["total"] += 1
            if r["outcome"] == "TP":
                by_tag[tag]["TP"] += 1
            elif r["outcome"] == "FN":
                by_tag[tag]["FN"] += 1

    breakdown = {}
    for tag, counts in sorted(by_tag.items(), key=lambda x: -x[1]["total"]):
        recall = counts["TP"] / counts["total"] if counts["total"] > 0 else 0
        breakdown[tag] = {
            "total": counts["total"],
            "detected": counts["TP"],
            "missed": counts["FN"],
            "recall": round(recall, 4),
        }
    return breakdown


# ── Main ───────────────────────────────────────────────────────────────────────

def generate_report(output_path=None, verbose=False):
    """Generate the full accuracy report."""
    start = time.time()

    scenarios = load_scenarios()
    if not scenarios:
        print("ERROR: No scenarios found. Set CYBERSEC_LAB env var.")
        sys.exit(1)

    print(f"Loaded {len(scenarios)} malicious scenarios")
    files = ensure_test_files(scenarios)
    print(f"Malicious test files ready: {len(files)}")

    benigns = load_benign_samples()
    print(f"Loaded {len(benigns)} benign samples from "
          f"{[str(d) for d in BENIGN_DIRS if d.exists()]}")

    results = []
    total_items = len(scenarios) + len(benigns)
    for i, s in enumerate(scenarios):
        name = s["name"]
        filepath = files.get(name)
        if not filepath:
            continue

        gt = compute_ground_truth(s)
        scanner_results = run_scanners(str(filepath))
        pred = compute_prediction(scanner_results)
        outcome = classify_outcome(gt, pred)

        results.append({
            "scenario": name,
            "file": str(filepath),
            "ground_truth": gt,
            "prediction": pred,
            "outcome": outcome,
        })

        if verbose:
            icon = "✅" if outcome == "TP" else "❌"
            print(f"  {icon} [{i+1:3d}/{total_items}] {name:50s} | {outcome}")

    for j, b in enumerate(benigns, start=len(scenarios) + 1):
        gt = {
            "label": "BENIGN",
            "severity": "none",
            "expected_detectors": [],
            "attack_techniques": [],
            "tags": ["benign"],
        }
        scanner_results = run_scanners(str(b["filepath"]))
        pred = compute_prediction(scanner_results)
        outcome = classify_outcome(gt, pred)

        results.append({
            "scenario": b["name"],
            "file": str(b["filepath"]),
            "ground_truth": gt,
            "prediction": pred,
            "outcome": outcome,
        })

        if verbose:
            icon = "✅" if outcome == "TN" else "⚠️ "
            print(f"  {icon} [{j:3d}/{total_items}] {b['name']:50s} | {outcome}")

    metrics = compute_metrics([r["outcome"] for r in results])
    per_severity = compute_per_severity(results)
    per_detector = compute_per_detector(results)
    per_tag = compute_per_tag(results)

    elapsed = time.time() - start

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pipeline": "MR. Robot Adversarial v1.0",
        "scanners": ["skill_scanner", "ioc_scanner", "yara", "secrets_detector"],
        "duration_seconds": round(elapsed, 2),
        "metrics": metrics,
        "per_severity": per_severity,
        "per_detector": per_detector,
        "per_tag": per_tag,
        "results": [
            {
                "scenario": r["scenario"],
                "file": r["file"],
                "gt": r["ground_truth"]["label"],
                "pred": r["prediction"]["label"],
                "outcome": r["outcome"],
                "severity": r["ground_truth"]["severity"],
                "findings": r["prediction"]["total_findings"],
                "detectors_flagged": r["prediction"]["detectors_flagged"],
            }
            for r in results
        ],
    }

    # Output
    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2))
        print(f"\nReport written to: {output_path}")

    # Print summary
    print()
    print("=" * 60)
    print("ACCURACY REPORT — MR. Robot Adversarial")
    print("=" * 60)
    print(f"Scenarios: {metrics['total']}")
    print(f"Duration:  {elapsed:.1f}s")
    print()
    print(f"  Accuracy:  {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.1f}%)")
    print(f"  Precision: {metrics['precision']:.4f} ({metrics['precision']*100:.1f}%)")
    print(f"  Recall:    {metrics['recall']:.4f} ({metrics['recall']*100:.1f}%)")
    print(f"  F1 Score:  {metrics['f1']:.4f}")
    print(f"  FPR:       {metrics['fpr']:.4f} ({metrics['fpr']*100:.1f}%)")
    print()
    cm = metrics["confusion_matrix"]
    print(f"  TP={cm['TP']}  FP={cm['FP']}  TN={cm['TN']}  FN={cm['FN']}")
    print()

    print("Per-Severity Breakdown:")
    print(f"  {'Severity':12s} {'Total':>5s} {'Detected':>8s} {'Missed':>6s} {'Recall':>7s}")
    print(f"  {'-'*12} {'-'*5} {'-'*8} {'-'*6} {'-'*7}")
    for sev, data in per_severity.items():
        print(f"  {sev:12s} {data['total']:>5d} {data['detected']:>8d} {data['missed']:>6d} {data['recall']*100:>6.1f}%")
    print()

    print("Per-Detector Breakdown:")
    print(f"  {'Detector':20s} {'Expected':>8s} {'Flagged':>7s} {'Rate':>7s}")
    print(f"  {'-'*20} {'-'*8} {'-'*7} {'-'*7}")
    for det, data in per_detector.items():
        print(f"  {det:20s} {data['expected']:>8d} {data['actually_flagged']:>7d} {data['detection_rate']*100:>6.1f}%")
    print()

    print("Per-Top-Tag Breakdown:")
    print(f"  {'Tag':30s} {'Total':>5s} {'Detected':>8s} {'Recall':>7s}")
    print(f"  {'-'*30} {'-'*5} {'-'*8} {'-'*7}")
    for tag, data in list(per_tag.items())[:10]:
        print(f"  {tag:30s} {data['total']:>5d} {data['detected']:>8d} {data['recall']*100:>6.1f}%")
    print()

    # Missed scenarios
    missed = [r for r in results if r["outcome"] == "FN"]
    if missed:
        print(f"Missed Scenarios ({len(missed)}):")
        for r in missed:
            print(f"  ❌ {r['scenario']:50s} (expected: {', '.join(r['ground_truth']['expected_detectors'])})")
        print()

    # False positives on benign samples
    false_positives = [r for r in results if r["outcome"] == "FP"]
    if false_positives:
        print(f"False Positives on Benign Samples ({len(false_positives)}):")
        for r in false_positives:
            print(f"  ⚠️  {r['scenario']:50s} (flagged by: {', '.join(r['prediction']['detectors_flagged'])})")
        print()

    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Generate Accuracy Report")
    ap.add_argument("--output", "-o", help="Output JSON path", default="docs/accuracy_report.json")
    ap.add_argument("--verbose", "-v", action="store_true", help="Print per-scenario results")
    args = ap.parse_args()
    generate_report(output_path=args.output, verbose=args.verbose)
