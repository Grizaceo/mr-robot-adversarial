"""Audit-trail tests for the orchestrator.

Verifies SANS requirement #8 ("every tool call is logged") end-to-end:
each pipeline stage (scanner / triage / falsifier) writes its own audit row
under a single orchestration run_id, and a genuine self-correction — a verdict
FLIP after the heterogeneous auditor challenges the triage — is recorded as a
`self_correction` row with before/after verdicts.
"""

import json

import pytest

import triage_orchestrator
import triage_falsifier
import agents.mr_robot.triage as triage_mod
import execution_logger


@pytest.fixture
def patched_pipeline(monkeypatch, tmp_path):
    # Real logger on an isolated DB so we can assert persisted rows.
    db = tmp_path / "audit.db"
    logger = execution_logger.ExecutionLogger(str(db))
    monkeypatch.setattr(execution_logger, "get_logger", lambda *a, **kw: logger)

    # Fake triage: first pass MALICIOUS@0.60 (routes to falsifier — below the 0.90
    # high-confidence bypass); the re-run (carrying falsifier context) flips to
    # BENIGN@0.95, simulating a genuine correction.
    def fake_triage(path, findings=None, context=None, json_output=False):
        if context is None:
            return {"verdict": "MALICIOUS", "confidence": 0.60, "severity": "high",
                    "summary": "looks bad", "findings": [],
                    "_meta": {"model": "nvidia/mistral-nemotron"}}
        return {"verdict": "BENIGN", "confidence": 0.95, "severity": "none",
                "summary": "framework-safe — false alarm", "findings": [],
                "_meta": {"model": "nvidia/mistral-nemotron"}}

    monkeypatch.setattr(triage_mod, "triage", fake_triage)

    # Fake falsifier (heterogeneous family — deepseek): FALSIFIED then SURVIVED.
    class FakeFalsifier:
        def __init__(self, provider=None):
            self.n = 0

        def falsify(self, report, candidate_path, scanner_findings=None):
            self.n += 1
            status = "FALSIFIED" if self.n == 1 else "SURVIVED"
            return {"status": status, "confidence": 0.8,
                    "summary": "eval() appears in a test harness",
                    "_meta": {"model": "deepseek-v4"}}

    monkeypatch.setattr(triage_falsifier, "TriageFalsifier", FakeFalsifier)
    return logger


def _rows(logger, tool):
    return logger.query(tool_name=tool, limit=100)


def test_orchestrator_logs_every_stage_under_one_run(patched_pipeline, tmp_path):
    candidate = tmp_path / "suspect.py"
    candidate.write_text("eval('1')\n")

    report = triage_orchestrator.orchestrate(
        str(candidate), scanner_findings={"skill_scanner": {"findings": []}}
    )
    assert report["final_verdict"]  # returns a verdict, no crash

    logger = patched_pipeline
    scanner_rows = _rows(logger, "scanner_sweep")
    triage_rows = _rows(logger, "triage")
    falsifier_rows = _rows(logger, "falsifier")

    assert scanner_rows, "scanner_sweep must be logged"
    assert triage_rows, "triage must be logged"
    assert falsifier_rows, "falsifier must be logged"

    # Per-stage agent attribution.
    assert scanner_rows[0]["agent_id"] == "scanner"
    assert triage_rows[0]["agent_id"] == "mr_robot"
    assert falsifier_rows[0]["agent_id"] == "falsifier"

    # Every stage is tied to a single orchestration run_id.
    run_ids = {r["run_id"] for r in scanner_rows + triage_rows + falsifier_rows}
    assert len(run_ids) == 1
    run_id = run_ids.pop()
    assert run_id.startswith("orch_")

    # get_run() returns the full decision chain for that run.
    chain = logger.get_run(run_id)
    tools = {r["tool_name"] for r in chain}
    assert {"scanner_sweep", "triage", "falsifier"}.issubset(tools)


def test_self_correction_flip_recorded(patched_pipeline, tmp_path):
    candidate = tmp_path / "suspect.py"
    candidate.write_text("eval('1')\n")

    triage_orchestrator.orchestrate(
        str(candidate), scanner_findings={"skill_scanner": {"findings": []}}
    )

    logger = patched_pipeline
    sc_rows = _rows(logger, "self_correction")
    assert sc_rows, "a self_correction row must be written when the verdict flips"

    out = json.loads(sc_rows[0]["output_json"])
    assert out["verdict_before"] == "MALICIOUS"
    assert out["verdict_after"] == "BENIGN"
    assert out["flipped"] is True


def test_trace_run_reconstructs_decision_chain(patched_pipeline, tmp_path):
    candidate = tmp_path / "suspect.py"
    candidate.write_text("eval('1')\n")

    triage_orchestrator.orchestrate(
        str(candidate), scanner_findings={"skill_scanner": {"findings": []}}
    )

    # --last behaviour: trace the most recent orchestration run.
    trace = triage_orchestrator.trace_run(None)
    assert trace["run_id"].startswith("orch_")
    assert trace["step_count"] >= 4  # scanner + triage + falsifier(s) + route
    tools = {s["tool"] for s in trace["steps"]}
    assert {"scanner_sweep", "triage", "falsifier", "self_correction"}.issubset(tools)
    # Outputs are parsed back to dicts (not raw JSON strings).
    sc = next(s for s in trace["steps"] if s["tool"] == "self_correction")
    assert sc["output"]["flipped"] is True


def test_no_self_correction_row_when_survived_first_pass(monkeypatch, tmp_path):
    """When the falsifier SURVIVES on the first pass, no flip is recorded."""
    db = tmp_path / "audit.db"
    logger = execution_logger.ExecutionLogger(str(db))
    monkeypatch.setattr(execution_logger, "get_logger", lambda *a, **kw: logger)

    def fake_triage(path, findings=None, context=None, json_output=False):
        return {"verdict": "MALICIOUS", "confidence": 0.70, "severity": "high",
                "summary": "looks bad", "findings": [],
                "_meta": {"model": "nvidia/mistral-nemotron"}}

    monkeypatch.setattr(triage_mod, "triage", fake_triage)

    class SurvivingFalsifier:
        def __init__(self, provider=None):
            pass

        def falsify(self, report, candidate_path, scanner_findings=None):
            return {"status": "SURVIVED", "confidence": 0.9, "summary": "no weakness",
                    "_meta": {"model": "deepseek-v4"}}

    monkeypatch.setattr(triage_falsifier, "TriageFalsifier", SurvivingFalsifier)

    candidate = tmp_path / "suspect.py"
    candidate.write_text("eval('1')\n")
    triage_orchestrator.orchestrate(
        str(candidate), scanner_findings={"skill_scanner": {"findings": []}}
    )

    # falsifier ran (and was logged) but the verdict never flipped.
    assert logger.query(tool_name="falsifier", limit=100)
    assert logger.query(tool_name="self_correction", limit=100) == []
