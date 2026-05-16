"""Tests for self-correction loop — Falsifier ↔ MR. Robot iterative refinement."""


import pytest
import triage_falsifier


@pytest.fixture
def benign_triage():
    return {
        "verdict": "BENIGN",
        "confidence": 0.96,
        "severity": "none",
        "summary": "Standard application code with no suspicious indicators.",
        "findings": [],
        "recommended_actions": [],
    }


@pytest.fixture
def low_confidence_triage():
    return {
        "verdict": "MALICIOUS",
        "confidence": 0.55,
        "severity": "medium",
        "summary": "Possibly malicious but uncertain.",
        "findings": [
            {"id": "F1", "description": "eval() call", "confidence": 0.45},
        ],
        "recommended_actions": ["investigate"],
    }


# ── Terminal condition: high confidence + SURVIVED falsification ────────


def test_loop_stops_when_survived(monkeypatch, tmp_path, benign_triage):
    """When triage confidence is high and Falsifier returns SURVIVED, stop immediately."""
    candidate = tmp_path / "safe.py"
    candidate.write_text("print('all good')\n")

    import agents.mr_robot.triage as triage_mod

    # Mock triage — returns high-confidence BENIGN
    def fake_triage(path, findings=None, context=None, json_output=False):
        return benign_triage.copy()

    monkeypatch.setattr(triage_mod, "triage", fake_triage)

    # Mock Falsifier — returns SURVIVED
    class FakeFalsifier:
        def falsify(self, triage_report, candidate_path, scanner_findings=None):
            return {
                "status": "SURVIVED",
                "confidence": 0.99,
                "summary": "No weaknesses found.",
                "challenges": [],
                "overall_assessment": "SURVIVED",
                "recommended_verdict": "BENIGN",
            }

    monkeypatch.setattr(triage_falsifier, "TriageFalsifier", FakeFalsifier)

    # Mock audit logger
    class FakeAudit:
        def log(self, *args, **kwargs):
            pass

    import execution_logger
    monkeypatch.setattr(execution_logger, "get_logger", lambda *a, **kw: FakeAudit())

    result = triage_falsifier.run_self_correction_loop(
        str(candidate), confidence_threshold=0.7, max_iterations=3
    )

    assert result["verdict"] == "BENIGN"
    assert result["confidence"] == 0.96
    assert result["_correction"]["iterations"] == 1
    assert result["_correction"]["falsifier_status"] == "SURVIVED"


# ── Correction path: FALSIFIED triggers re-evaluation ────────────────────


def test_loop_reruns_when_falsified(monkeypatch, tmp_path, low_confidence_triage):
    """When Falsifier returns FALSIFIED, re-run triage with counter-argument."""
    candidate = tmp_path / "suspicious.py"
    candidate.write_text("eval('print(1)')\n")

    import agents.mr_robot.triage as triage_mod

    triage_calls = []

    def fake_triage(path, findings=None, context=None, json_output=False):
        triage_calls.append(context)
        result = low_confidence_triage.copy()
        if context is not None and context.get("falsifier_challenge"):
            # On re-run, bump confidence to simulate refinement
            result["confidence"] = 0.82
            result["verdict"] = "SUSPICIOUS"
            result["summary"] = "Re-evaluated: severity reduced after considering context."
        return result

    monkeypatch.setattr(triage_mod, "triage", fake_triage)

    class FakeFalsifier:
        call_count = 0

        def falsify(self, triage_report, candidate_path, scanner_findings=None):
            self.call_count += 1
            if self.call_count == 1:
                # First call: FALSIFIED
                return {
                    "status": "FALSIFIED",
                    "confidence": 0.80,
                    "summary": "The eval() call may be in a test harness — not necessarily malicious.",
                    "challenges": [
                        {
                            "finding_challenged": "F1",
                            "counter_argument": "Context suggests this is test code",
                            "severity": "medium",
                            "evidence": "File path includes /tests/",
                        }
                    ],
                    "overall_assessment": "FALSIFIED — one finding is questionable.",
                    "recommended_verdict": "SUSPICIOUS",
                }
            else:
                # Second call: SURVIVED
                return {
                    "status": "SURVIVED",
                    "confidence": 0.90,
                    "summary": "Revised triage is adequate.",
                    "challenges": [],
                    "overall_assessment": "SURVIVED",
                    "recommended_verdict": "SUSPICIOUS",
                }

    monkeypatch.setattr(triage_falsifier, "TriageFalsifier", FakeFalsifier)

    class FakeAudit:
        def log(self, *args, **kwargs):
            pass

    import execution_logger
    monkeypatch.setattr(execution_logger, "get_logger", lambda *a, **kw: FakeAudit())

    result = triage_falsifier.run_self_correction_loop(
        str(candidate), confidence_threshold=0.7, max_iterations=3
    )

    # Should have been called at least twice (initial + at least 1 re-run)
    assert len(triage_calls) >= 2
    # The re-run should have received falsifier context
    assert any(c and "falsifier_challenge" in c for c in triage_calls if c)
    # Final result should reflect the refined evaluation
    assert result["confidence"] >= 0.7
    assert result["_correction"]["iterations"] >= 1


# ── Iteration cap ────────────────────────────────────────────────────────


def test_loop_respects_max_iterations(monkeypatch, tmp_path):
    """The loop MUST stop after max_iterations, even if Falsifier keeps saying FALSIFIED."""
    candidate = tmp_path / "stubborn.py"
    candidate.write_text("obfuscated = True\n")

    stubborn_triage = {
        "verdict": "MALICIOUS",
        "confidence": 0.40,
        "severity": "high",
        "summary": "Still looks bad.",
        "findings": [{"id": "F1", "description": "obfuscation", "confidence": 0.40}],
        "recommended_actions": ["investigate"],
    }

    import agents.mr_robot.triage as triage_mod

    triage_call_count = [0]

    def fake_triage(path, findings=None, context=None, json_output=False):
        triage_call_count[0] += 1
        return stubborn_triage.copy()

    monkeypatch.setattr(triage_mod, "triage", fake_triage)

    class AlwaysFalsified:
        def falsify(self, triage_report, candidate_path, scanner_findings=None):
            return {
                "status": "FALSIFIED",
                "confidence": 0.99,
                "summary": "Still unconvinced.",
                "challenges": [],
                "overall_assessment": "FALSIFIED",
                "recommended_verdict": "INCONCLUSIVE",
            }

    monkeypatch.setattr(triage_falsifier, "TriageFalsifier", AlwaysFalsified)

    class FakeAudit:
        def log(self, *args, **kwargs):
            pass

    import execution_logger
    monkeypatch.setattr(execution_logger, "get_logger", lambda *a, **kw: FakeAudit())

    result = triage_falsifier.run_self_correction_loop(
        str(candidate), confidence_threshold=0.7, max_iterations=3
    )

    # Must have called triage exactly max_iterations times
    assert triage_call_count[0] == 3
    # Must have iteration count = max_iterations
    assert result["_correction"]["iterations"] == 3
    # Result should still be the stubborn verdict (loop didn't converge)
    assert result["verdict"] == "MALICIOUS"


# ── Missing file ─────────────────────────────────────────────────────────


def test_loop_handles_missing_file(tmp_path):
    """When candidate doesn't exist, should still return a result (handled by triage)."""
    # The triage function itself handles missing files, so the loop should
    # delegate to triage and return whatever triage gives back.
    # This test just verifies the loop doesn't crash.
    result = triage_falsifier.run_self_correction_loop(
        str(tmp_path / "does_not_exist.py"), max_iterations=1
    )
    assert isinstance(result, dict)
