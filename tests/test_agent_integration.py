#!/usr/bin/env python3
"""Smoke tests for the active FIND EVIL! core pipeline."""

from mcp_server import mcp
from mcp_tools import aggregate_scanner_results, verdict_to_severity


def test_core_imports():
    assert mcp is not None


def test_scanner_aggregation_benign():
    results = {
        "skill_scanner": {"findings": []},
        "ioc_scanner": {"findings": []},
        "yara": {"findings": []},
        "secrets_detector": {"findings": []},
    }
    summary = aggregate_scanner_results(results)
    assert summary["overall_verdict"] == "BENIGN"
    assert verdict_to_severity(summary["overall_verdict"]) == "none"


def test_scanner_aggregation_malicious():
    results = {
        "skill_scanner": {"findings": [{"severity": "CRITICAL"}]},
        "ioc_scanner": {"findings": []},
        "yara": {"findings": []},
        "secrets_detector": {"findings": []},
    }
    summary = aggregate_scanner_results(results)
    assert summary["overall_verdict"] == "MALICIOUS"
    assert verdict_to_severity(summary["overall_verdict"]) == "critical"
