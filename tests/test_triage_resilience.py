from agents.mr_robot import triage as triage_mod


def test_triage_falls_back_to_next_provider(monkeypatch, tmp_path):
    candidate = tmp_path / "sample.py"
    candidate.write_text("print('ok')\n")

    calls = []

    def fake_call_llm(provider, prompt, system=""):
        calls.append(provider)
        if provider == "nvidia-nim":
            raise RuntimeError("provider down")
        return ('{"verdict":"BENIGN","confidence":0.99,"severity":"none","summary":"ok","findings":[],"recommended_actions":[]}', 'fake-model')

    monkeypatch.setattr(triage_mod, "_call_llm", fake_call_llm)
    monkeypatch.setattr(triage_mod, "FALLBACK_PROVIDER_ORDER", ["nvidia-nim", "ollama-cloud", "openrouter"], raising=False)

    report = triage_mod.triage(str(candidate), provider="nvidia-nim", json_output=True)
    assert report["verdict"] == "BENIGN"
    assert report["_meta"]["provider"] == "ollama-cloud"
    assert calls == ["nvidia-nim", "ollama-cloud"]


def test_triage_returns_inconclusive_for_large_file(monkeypatch, tmp_path):
    candidate = tmp_path / "big.js"
    candidate.write_text("A" * 60001)
    monkeypatch.setenv("MR_ROBOT_MAX_TRIAGE_FILE_BYTES", "50000")

    def should_not_run(*args, **kwargs):
        raise AssertionError("LLM should not be called for oversized files")

    monkeypatch.setattr(triage_mod, "_call_llm", should_not_run)

    report = triage_mod.triage(str(candidate), provider="nvidia-nim", json_output=True)
    assert report["verdict"] == "INCONCLUSIVE"
    assert "too large" in report["summary"].lower()
    assert report["recommended_actions"] == ["manual_review"]


# ── System Prompt Integrity Tests ──────────────────────────────────────────────

def test_system_prompt_has_5_phase_workflow():
    """Verify the system prompt includes all 5 phases."""
    from agents.mr_robot.triage import SYSTEM_PROMPT
    assert "Phase 1" in SYSTEM_PROMPT
    assert "Phase 2" in SYSTEM_PROMPT
    assert "Phase 3" in SYSTEM_PROMPT
    assert "Phase 4" in SYSTEM_PROMPT
    assert "Phase 5" in SYSTEM_PROMPT
    assert "INPUT GATHERING" in SYSTEM_PROMPT
    assert "ATTACK SURFACE MAPPING" in SYSTEM_PROMPT
    assert "SECURITY CHECKLIST" in SYSTEM_PROMPT
    assert "VERIFICATION" in SYSTEM_PROMPT
    assert "PRE-CONCLUSION AUDIT" in SYSTEM_PROMPT


def test_system_prompt_has_confidence_levels():
    """Verify the system prompt defines HIGH/MEDIUM/LOW confidence levels."""
    from agents.mr_robot.triage import SYSTEM_PROMPT
    assert "HIGH" in SYSTEM_PROMPT
    assert "MEDIUM" in SYSTEM_PROMPT
    assert "LOW" in SYSTEM_PROMPT
    assert "confidence_level" in SYSTEM_PROMPT


def test_system_prompt_has_framework_safe_patterns():
    """Verify the system prompt includes framework-mitigated patterns."""
    from agents.mr_robot.triage import SYSTEM_PROMPT
    assert "FRAMEWORK SAFE PATTERNS" in SYSTEM_PROMPT
    assert "auto-escaped" in SYSTEM_PROMPT
    assert "parameterized" in SYSTEM_PROMPT.lower() or "parameterized" in SYSTEM_PROMPT


def test_system_prompt_has_injection_patterns():
    """Verify the system prompt includes injection detection patterns."""
    from agents.mr_robot.triage import SYSTEM_PROMPT
    assert "ignore previous instructions" in SYSTEM_PROMPT
    assert "INJECTION PATTERNS" in SYSTEM_PROMPT
    assert "delimiter" in SYSTEM_PROMPT.lower()


def test_system_prompt_output_format_has_new_fields():
    """Verify the output format includes all new fields."""
    from agents.mr_robot.triage import SYSTEM_PROMPT
    assert "confidence_level" in SYSTEM_PROMPT
    assert "attack_surface" in SYSTEM_PROMPT
    assert "checklist_coverage" in SYSTEM_PROMPT
    assert "phase5_audit" in SYSTEM_PROMPT
    assert "data_flow" in SYSTEM_PROMPT


def test_parse_json_response_handles_new_fields():
    """Verify _parse_json_response preserves new fields."""
    from agents.mr_robot.triage import _parse_json_response
    raw = '{"verdict":"MALICIOUS","confidence":0.95,"confidence_level":"HIGH","severity":"critical","summary":"test","attack_surface":["input"],"findings":[{"type":"technique","description":"eval()","evidence":"line 5","mitre_id":"T1059","confidence":"HIGH","data_flow":"input->eval"}],"false_positive_likelihood":0.05,"recommended_actions":["quarantine"],"scanner_correlation":"agrees","checklist_coverage":{"injection":"flagged","xss":"clean"},"phase5_audit":{"files_reviewed":["test.py"],"checklist_items_checked":12,"areas_not_verified":[]}}'
    result = _parse_json_response(raw)
    assert result["confidence_level"] == "HIGH"
    assert result["attack_surface"] == ["input"]
    assert result["checklist_coverage"]["injection"] == "flagged"
    assert result["phase5_audit"]["checklist_items_checked"] == 12
    assert result["findings"][0]["data_flow"] == "input->eval"


def test_parse_json_response_error_includes_new_fields():
    """Verify error response includes new fields with defaults."""
    from agents.mr_robot.triage import _parse_json_response
    result = _parse_json_response("not json")
    assert "confidence_level" in result
    assert "attack_surface" in result
    assert "checklist_coverage" in result
    assert "phase5_audit" in result
