#!/usr/bin/env python3
"""
Scenario Coverage Test — MR. Robot Adversarial
===============================================

Runs all cybersecurity-lab scenarios through the scanner suite
and reports coverage metrics per scanner, per severity, per technique.

REQUIRES: CYBERSEC_LAB env var or cybersecurity-lab at default path.

Usage:
    pytest tests/test_scenario_coverage.py -v
    pytest tests/test_scenario_coverage.py -v -k "test_all_scenarios_detected_by_at_least_one"
    python tests/test_scenario_coverage.py --report   # standalone report
"""

import json
import os
import time
from collections import defaultdict
from pathlib import Path

import pytest

# ── Resolve cybersecurity-lab path ────────────────────────────────────────

LAB_ROOT = Path(os.environ.get("CYBERSEC_LAB",
                str(Path.home() / ".hermes" / "workspace" / "cybersecurity-lab")))
SCENARIOS_DIR = LAB_ROOT / "scenarios"

# Test corpus: writable override (container-safe), fallback to lab path
TEST_CORPUS = Path(os.environ.get("TEST_CORPUS_OVERRIDE",
                   str(LAB_ROOT / "test-corpus")))

pytestmark = pytest.mark.skipif(
    not SCENARIOS_DIR.exists(),
    reason=f"cybersecurity-lab not found at {LAB_ROOT}. Set CYBERSEC_LAB env var."
)


def _load_scenarios():
    """Load all valid scenarios from the lab. Returns list of dicts."""
    scenarios = []
    for path in sorted(SCENARIOS_DIR.glob("*.json")):
        if path.name.startswith("_"):
            continue
        try:
            doc = json.loads(path.read_text())
            scenarios.append(doc)
        except json.JSONDecodeError:
            continue
    return scenarios


def _ensure_test_files(scenarios: list[dict]) -> dict[str, Path]:
    """Ensure every scenario has a test file. Returns {scenario_name: file_path}."""
    mapping = {}
    for s in scenarios:
        filename = s.get("filename", "")
        if not filename:
            continue
        # Check both malicious and benign dirs
        for subdir in ("malicious", "benign"):
            candidate = TEST_CORPUS / subdir / filename
            if candidate.exists():
                mapping[s["name"]] = candidate
                break
        else:
            # Generate on-the-fly if missing
            out_dir = TEST_CORPUS / "malicious"
            out_path = out_dir / filename
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(s.get("payload", ""))
            mapping[s["name"]] = out_path
    return mapping


def _run_scanners(filepath: str) -> dict:
    """Run all 4 core scanners on a file."""
    from mcp_tools import run_all_scanners
    return run_all_scanners(str(filepath))


def _count_findings(scanner_results: dict) -> int:
    """Count total findings across all scanners."""
    total = 0
    for name, result in scanner_results.items():
        if isinstance(result, dict):
            findings = result.get("findings", [])
            if isinstance(findings, list):
                total += len(findings)
    return total


# ── Fixtures ───────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def all_scenarios():
    """Load all scenarios once per test module."""
    scenarios = _load_scenarios()
    assert len(scenarios) > 0, "No scenarios loaded — is CYBERSEC_LAB set?"
    return scenarios


@pytest.fixture(scope="module")
def scenario_files(all_scenarios):
    """Generate/locate test files for all scenarios."""
    return _ensure_test_files(all_scenarios)


# ── Tests ──────────────────────────────────────────────────────────────────


class TestScenarioCoverage:
    """Mass-coverage tests across all scenarios."""

    def test_scenarios_exist(self, all_scenarios):
        """At least 90 scenarios are loaded."""
        assert len(all_scenarios) >= 90, f"Only {len(all_scenarios)} scenarios"

    def test_all_scenarios_have_payload(self, all_scenarios):
        """Every scenario has a non-empty payload."""
        missing = [s["name"] for s in all_scenarios if not s.get("payload")]
        assert not missing, f"Missing payloads: {missing}"

    def test_all_scenarios_have_expected_detectors(self, all_scenarios):
        """Every scenario lists at least one expected detector."""
        missing = [s["name"] for s in all_scenarios if not s.get("expected_detectors")]
        assert not missing, f"Missing expected_detectors: {missing}"

    def test_scanner_coverage_above_50_percent(self, all_scenarios, scenario_files):
        """At least 50% of scenarios are detected by at least one scanner."""
        detected = 0
        undetected = []
        for s in all_scenarios:
            name = s["name"]
            filepath = scenario_files.get(name)
            if not filepath:
                continue
            results = _run_scanners(str(filepath))
            if _count_findings(results) > 0:
                detected += 1
            else:
                undetected.append(name)

        total = len(scenario_files)
        rate = detected / total * 100 if total > 0 else 0
        print(f"\n  Scanner coverage: {detected}/{total} ({rate:.1f}%)")
        if undetected:
            print(f"  Undetected ({len(undetected)}):")
            for name in undetected[:10]:
                print(f"    - {name}")
            if len(undetected) > 10:
                print(f"    ... and {len(undetected) - 10} more")

        assert rate >= 50.0, f"Coverage {rate:.1f}% below 50% threshold"

    def test_critical_scenarios_all_detected(self, all_scenarios, scenario_files):
        """At least 90% of CRITICAL severity scenarios must be detected.
        
        Known gaps (2026-05-15):
        - adversarial-kubernetes-snake-in-the-pod: YAML-only, no code IOCs
        - adversarial-pypi-ai-agent-hijack: subtle AI agent hijack vector
        - ai-discovered-zero-day-exploit: novel technique, no rules yet
        These require YARA rule additions or AST-level analysis.
        """
        critical = [s for s in all_scenarios if s.get("severity") == "critical"]
        undetected = []
        for s in critical:
            name = s["name"]
            filepath = scenario_files.get(name)
            if not filepath:
                continue
            results = _run_scanners(str(filepath))
            if _count_findings(results) == 0:
                undetected.append(name)

        if undetected:
            total_crit = len(critical)
            detected_crit = total_crit - len(undetected)
            rate_crit = detected_crit / total_crit * 100 if total_crit > 0 else 100
            print(f"\n  Critical detection: {detected_crit}/{total_crit} ({rate_crit:.1f}%)")
            print(f"  Undetected: {undetected}")
        assert len(undetected) <= len(critical) * 0.10, \
            f"{len(undetected)}/{len(critical)} critical undetected (>{10}% allowed)"

    def test_yara_coverage_above_40_percent(self, all_scenarios, scenario_files):
        """YARA should detect at least 40% of scenarios (89 scenarios expect it)."""
        yara_detected = 0
        total = 0
        for s in all_scenarios:
            filepath = scenario_files.get(s["name"])
            if not filepath:
                continue
            total += 1
            results = _run_scanners(str(filepath))
            yara_result = results.get("yara", {})
            if isinstance(yara_result, dict):
                findings = yara_result.get("findings", [])
                if isinstance(findings, list) and len(findings) > 0:
                    yara_detected += 1

        rate = yara_detected / total * 100 if total > 0 else 0
        print(f"\n  YARA coverage: {yara_detected}/{total} ({rate:.1f}%)")
        assert rate >= 40.0, f"YARA coverage {rate:.1f}% below 40%"


class TestScannerSpecificity:
    """Per-scanner breakdown metrics."""

    def test_per_scanner_stats(self, all_scenarios, scenario_files):
        """Print per-scanner detection stats (always passes, informative only)."""
        scanner_hits = defaultdict(int)
        total = 0
        for s in all_scenarios:
            filepath = scenario_files.get(s["name"])
            if not filepath:
                continue
            total += 1
            results = _run_scanners(str(filepath))
            for scanner_name in ("skill_scanner", "ioc_scanner", "yara", "secrets_detector"):
                r = results.get(scanner_name, {})
                if isinstance(r, dict):
                    findings = r.get("findings", [])
                    if isinstance(findings, list) and len(findings) > 0:
                        scanner_hits[scanner_name] += 1

        print(f"\n  Total scenarios tested: {total}")
        print(f"  {'Scanner':25s} {'Detected':>8s}  {'Rate':>6s}")
        print(f"  {'-'*25} {'-'*8}  {'-'*6}")
        for scanner in ("skill_scanner", "ioc_scanner", "yara", "secrets_detector"):
            hits = scanner_hits[scanner]
            rate = hits / total * 100 if total > 0 else 0
            print(f"  {scanner:25s} {hits:>5}/{total:<5} {rate:>5.1f}%")

        # No hard assertion — this is informative. But YARA must detect something.
        assert scanner_hits["yara"] > 0, "YARA detected nothing — check rules"


# ── Standalone runner ──────────────────────────────────────────────────────

if __name__ == "__main__":
    scenarios = _load_scenarios()
    files = _ensure_test_files(scenarios)

    print(f"Scenarios: {len(scenarios)}")
    print(f"Test files: {len(files)}")
    print()

    detected = 0
    undetected = []
    start = time.time()

    for name, filepath in sorted(files.items()):
        results = _run_scanners(str(filepath))
        n = _count_findings(results)
        if n > 0:
            detected += 1
        else:
            undetected.append(name)
        print(f"  {'[HIT]' if n > 0 else '[MISS]'} {name:50s} ({n:2d} findings)")

    elapsed = time.time() - start
    print(f"\nDetected: {detected}/{len(files)} ({detected/len(files)*100:.1f}%)")
    print(f"Undetected: {len(undetected)}")
    print(f"Time: {elapsed:.1f}s ({elapsed/len(files)*1000:.0f}ms per scenario)")
