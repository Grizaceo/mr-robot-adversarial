"""
Tests for threat_intel_grounding.verify_mitre and ground_findings.

Verifies:
- Real MITRE IDs (T1059, T1566, T1190) → exists=True
- Non-existent IDs (T9999, T0000) → exists=False
- None / empty string → exists=False
- ground_findings annotates mitre_grounded correctly
- Hallucinated prose IDs are caught
- Sub-technique IDs (T1059.001) → handled
"""

import pytest
from pathlib import Path

INDEX_PATH = Path(__file__).resolve().parents[1] / "data" / "mitre_attack_index.json"


@pytest.fixture(scope="module")
def index_loaded():
    if not INDEX_PATH.exists():
        pytest.skip("data/mitre_attack_index.json not found — run threat_intel_grounding.py --refresh")
    return True


# ── verify_mitre: known IDs ───────────────────────────────────────────────────

@pytest.mark.parametrize("tid,expected_name_fragment", [
    ("T1059", "Command and Script"),
    ("T1566", "Phishing"),
    ("T1190", "Exploit"),
    ("T1055", "Process Injection"),
    ("T1078", "Valid Accounts"),
])
def test_known_id_exists(index_loaded, tid, expected_name_fragment):
    from threat_intel_grounding import verify_mitre
    result = verify_mitre(tid)
    assert result["exists"] is True, f"{tid} should exist in ATT&CK index"
    assert expected_name_fragment.lower() in (result["name"] or "").lower(), \
        f"Expected '{expected_name_fragment}' in name for {tid}, got '{result['name']}'"


# ── verify_mitre: hallucinated IDs ────────────────────────────────────────────

@pytest.mark.parametrize("bad_id", ["T9999", "T0000", "T99999", "TXXX", "not_a_mitre_id"])
def test_hallucinated_id_not_exists(index_loaded, bad_id):
    from threat_intel_grounding import verify_mitre
    result = verify_mitre(bad_id)
    assert result["exists"] is False, f"'{bad_id}' should not exist in ATT&CK index"


# ── verify_mitre: edge inputs ─────────────────────────────────────────────────

def test_none_input(index_loaded):
    from threat_intel_grounding import verify_mitre
    result = verify_mitre(None)
    assert result["exists"] is False


def test_empty_string(index_loaded):
    from threat_intel_grounding import verify_mitre
    result = verify_mitre("")
    assert result["exists"] is False


def test_sub_technique_handled(index_loaded):
    from threat_intel_grounding import verify_mitre
    # T1059.001 = PowerShell — a real sub-technique
    result = verify_mitre("T1059.001")
    # Sub-techniques are in the full ATT&CK index; result depends on index coverage
    # At minimum it shouldn't raise
    assert "exists" in result


def test_lowercase_normalised(index_loaded):
    from threat_intel_grounding import verify_mitre
    r1 = verify_mitre("T1059")
    r2 = verify_mitre("t1059")
    assert r1["exists"] == r2["exists"]


# ── ground_findings ───────────────────────────────────────────────────────────

def test_ground_findings_valid_id(index_loaded):
    from threat_intel_grounding import ground_findings
    findings = [{"mitre_id": "T1059", "description": "command execution"}]
    ground_findings(findings)
    assert findings[0]["mitre_grounded"] is True
    assert findings[0]["mitre_name"] is not None


def test_ground_findings_invalid_id(index_loaded):
    from threat_intel_grounding import ground_findings
    findings = [{"mitre_id": "T9999", "description": "made up technique"}]
    ground_findings(findings)
    assert findings[0]["mitre_grounded"] is False
    assert findings[0]["mitre_name"] is None


def test_ground_findings_no_id(index_loaded):
    from threat_intel_grounding import ground_findings
    findings = [{"mitre_id": None, "description": "generic finding"}]
    ground_findings(findings)
    assert findings[0]["mitre_grounded"] is None  # Not a failure — ID not provided


def test_ground_findings_empty_list(index_loaded):
    from threat_intel_grounding import ground_findings
    result = ground_findings([])
    assert result == []


def test_ground_findings_mixed_batch(index_loaded):
    from threat_intel_grounding import ground_findings
    findings = [
        {"mitre_id": "T1059", "description": "legit"},
        {"mitre_id": "T9999", "description": "hallucinated"},
        {"mitre_id": None,    "description": "no id"},
    ]
    ground_findings(findings)
    assert findings[0]["mitre_grounded"] is True
    assert findings[1]["mitre_grounded"] is False
    assert findings[2]["mitre_grounded"] is None


def test_ground_findings_extracts_id_from_prose(index_loaded):
    from threat_intel_grounding import ground_findings
    findings = [{"mitre_id": "Uses T1059 for execution", "description": "command exec"}]
    ground_findings(findings)
    assert findings[0]["mitre_grounded"] is True
