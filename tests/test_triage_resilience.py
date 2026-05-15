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
