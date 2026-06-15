"""
Accuracy-threshold regression tests.

These tests assert that the accuracy report on disk stays above the thresholds
that qualified the submission for SANS FIND EVIL! 2026.  If scanner rules or the
corpus change, the report must be regenerated *and* these thresholds must
continue to pass — or the change must be explicitly reviewed.

Run:
    pytest tests/test_accuracy_thresholds.py -v
"""

import json
import pytest
from pathlib import Path

REPORT_PATH = Path(__file__).resolve().parents[1] / "docs" / "accuracy_report.json"


@pytest.fixture(scope="module")
def report():
    assert REPORT_PATH.exists(), f"accuracy_report.json not found at {REPORT_PATH}; run generate_accuracy_report.py first."
    return json.loads(REPORT_PATH.read_text())


@pytest.fixture(scope="module")
def metrics(report):
    """Extract the metrics dict from wherever it lives in the report."""
    # Structure: report["metrics"] has accuracy/precision/recall/f1/fpr + confusion_matrix
    m = report.get("metrics", {})
    cm = m.get("confusion_matrix", {})
    return {
        "FP": cm.get("FP", m.get("FP", 0)),
        "FN": cm.get("FN", m.get("FN", 0)),
        "TP": cm.get("TP", m.get("TP", 0)),
        "TN": cm.get("TN", m.get("TN", 0)),
        "precision": m.get("precision"),
        "recall":    m.get("recall"),
        "f1":        m.get("f1"),
        "fpr":       m.get("fpr"),
    }


def test_report_exists(report):
    assert "metrics" in report or "summary" in report, \
        "report must have a metrics or summary section"


def test_recall_is_1(metrics):
    """No malicious sample must be missed (FN=0)."""
    fn = metrics["FN"]
    assert fn == 0, f"Expected FN=0, got FN={fn} — a malicious sample was missed"


def test_fpr_below_threshold(metrics):
    """False-positive rate must be below 10%."""
    fpr = metrics["fpr"]
    if fpr is None:
        fp, tn = metrics["FP"], metrics["TN"]
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    assert fpr <= 0.10, f"FPR {fpr:.1%} exceeds 10% threshold"


def test_precision_above_threshold(metrics):
    """Precision must be ≥ 97%."""
    precision = metrics["precision"]
    if precision is None:
        tp, fp = metrics["TP"], metrics["FP"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    assert precision >= 0.97, f"Precision {precision:.1%} below 97% threshold"


def test_f1_above_threshold(metrics):
    """F1 ≥ 0.98."""
    f1 = metrics["f1"]
    if f1 is None:
        tp, fp, fn = metrics["TP"], metrics["FP"], metrics["FN"]
        denom = 2 * tp + fp + fn
        f1 = (2 * tp / denom) if denom else 0.0
    assert f1 >= 0.98, f"F1 {f1:.3f} below 0.98 threshold"


def test_benign_corpus_covered(metrics):
    """Report must cover the full benign corpus: 38 samples (12 in benign_corpus/ +
    26 in cybersecurity-lab/test-corpus/benign/). Floor guards against silently
    dropping benigns (which would inflate precision); growth still passes."""
    total_benign = metrics["TN"] + metrics["FP"]
    assert total_benign >= 38, f"Only {total_benign} benign samples in report; expected ≥ 38"
