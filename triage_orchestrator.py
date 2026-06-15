#!/usr/bin/env python3
"""
Triage Orchestrator — Heterogeneous Agent Coordinator
=====================================================

Orchestrates the MR. Robot Adversarial pipeline with the heterogeneity
mandate formalized by Shehata & Li (2026).

THEORY (arXiv:2604.27274):
  The Inverse-Wisdom Law proves that in kinship-dominant agent swarms
  (same model family in propagator → auditor → synthesizer), adding
  more agents *increases* error stability rather than reducing it.
  The solution: heterogeneous synthesizer with τ≈0.

  μ = σ(1 − B) + τB        (Synthesizer Gating Theorem)
  τ ∝ ω · (1 − ΔA)         (Architectural Tribalism)

  Reinforced by prior multi-agent diversity literature:
  Du et al. 2023 (arXiv:2305.14325), Wang et al. 2022 (arXiv:2203.11171),
  Liang et al. 2023 (arXiv:2305.19118), Sharma et al. 2023 (arXiv:2310.13548).

ARCHITECTURE:
  ┌──────────────────────────────────────────────────────────┐
  │ Scanner Suite (YARA / skill / IOC / secrets)             │
  │ → deterministic, τ=0 by definition                       │
  └────────────────────────┬─────────────────────────────────┘
                           │
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │ MR. Robot (Nemotron, propagator)                         │
  │ → Initial triage: MALICIOUS / BENIGN / INCONCLUSIVE      │
  └────────────────────────┬─────────────────────────────────┘
                           │
              ┌────────────┴────────────┐
              │                         │
              ▼                         ▼
    ┌─────────────────┐       ┌─────────────────────┐
    │ HIGH CONFIDENCE  │       │ DUDOSO / BAJA CONF  │
    │ + scanners clean │       │ o veredictos mixtos │
    └────────┬────────┘       └──────────┬──────────┘
             │                           │
             │                           ▼
             │              ┌──────────────────────────┐
             │              │ Falsifier (DeepSeek)      │
             │              │ → ΔA alto vs Nemotron     │
             │              │ → τ bajo, kinship roto    │
             │              └──────────┬───────────────┘
             │                         │
             │              ┌──────────┴──────────┐
             │              │ SURVIVED  │FALSIFIED│
             │              │ → accept  │→ re-run │
             │              │           │  (max 2)│
             │              └─────┬─────┘────┬────┘
             │                    │          │
             ▼                    ▼          ▼
  ┌──────────────────────────────────────────────────────────┐
  │ ORCHESTRATOR (rule-based, τ=0)                           │
  │ → NO LLM — purely deterministic                          │
  │ → Final verdict synthesizer                              │
  │ → Tracks all decisions in audit log                      │
  │ → Flags for human review if disagreement persists        │
  └──────────────────────────────────────────────────────────┘

Primary Reference:
  Shehata, D. & Li, M. (2026). "The Inverse-Wisdom Law: Architectural
  Tribalism and the Consensus Paradox in Agentic Swarms."
  arXiv:2604.27274. University of Waterloo.

Supporting Literature:
  - Du et al. (2023). Multiagent Debate. arXiv:2305.14325.
  - Wang et al. (2022). Self-Consistency. arXiv:2203.11171.
  - Liang et al. (2023). Divergent Thinking in Multi-Agent Debate. arXiv:2305.19118.
  - Sharma et al. (2023). LLM Sycophancy. arXiv:2310.13548.

Usage:
    from triage_orchestrator import orchestrate
    report = orchestrate("/path/to/candidate.py")
"""

import json
import os
import time
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("triage-orchestrator")

# ── Heuristic thresholds (tunable) ──────────────────────────────────────────

HIGH_CONFIDENCE_STRAIGHT_TO_VERDICT = 0.90   # Scanner + MR. Robot agree
FALSIFIER_TRIGGER_CONFIDENCE = 0.85           # Below this → falsifier required
MAX_CORRECTION_ITERATIONS = 2                 # Paper says >2 with same family is harmful
HUMAN_FLAG_THRESHOLD = 2                      # Disagreements after max iters → human

# ── Model families for heterogeneity tracking ───────────────────────────────

MODEL_FAMILIES = {
    "nemotron": "nvidia-nemotron",        # Nemotron: MR. Robot default
    "deepseek": "deepseek",               # DeepSeek: Falsifier (ΔA alto vs Nemotron)
    "llama": "meta-llama",                # Llama: auditor fallback
    "mistral": "mistral",                 # Mistral: another family
}

def _detect_family(model_name: str) -> str:
    """Heuristic model family detection from model name."""
    model_lower = model_name.lower()
    # Order matters: NVIDIA Nemotron variants also carry "llama"/"mistral" in their
    # names, so nemotron must be matched first to attribute them correctly.
    for family_id, keywords in [
        ("nemotron", ["nemotron", "nvidia"]),
        ("deepseek", ["deepseek"]),
        ("gpt-oss", ["gpt-oss", "gpt_oss", "openai"]),
        ("llama", ["llama"]),
        ("mistral", ["mistral"]),
        ("qwen", ["qwen"]),
        ("minimax", ["minimax"]),
        ("glm", ["glm", "z-ai"]),
        ("gemma", ["gemma"]),
        ("kimi", ["kimi"]),
    ]:
        if any(kw in model_lower for kw in keywords):
            return family_id
    return "unknown"


def _check_heterogeneity(propagator_model: str, auditor_model: str) -> dict:
    """
    Compute architectural distance ΔA between model families.
    Returns diagnostics for audit trail.
    """
    p_family = _detect_family(propagator_model)
    a_family = _detect_family(auditor_model)

    same_family = (p_family == a_family and p_family != "unknown")

    return {
        "propagator_family": p_family,
        "auditor_family": a_family,
        "architectural_distance": 1.0 if p_family != a_family else 0.0,
        "kinship_lock_risk": "HIGH" if same_family else "LOW",
        "heterogeneity_mandate_met": p_family != a_family,
    }


def _proof_summary(triage_report: dict) -> dict:
    """
    Summarise proof_status annotations from triage findings.
    Returns counts and a flag indicating whether all findings are REFUTED.
    """
    findings = triage_report.get("findings") or []
    counts: dict[str, int] = {"CONFIRMED": 0, "INFERRED": 0, "REFUTED": 0, "unknown": 0}
    for f in findings:
        status = f.get("proof_status") or "unknown"
        counts[status] = counts.get(status, 0) + 1
    non_refuted = counts["CONFIRMED"] + counts["INFERRED"] + counts["unknown"]
    all_refuted = len(findings) > 0 and non_refuted == 0
    grounded = sum(1 for f in findings if f.get("mitre_grounded") is True)
    return {
        "confirmed": counts["CONFIRMED"],
        "inferred": counts["INFERRED"],
        "refuted": counts["REFUTED"],
        "all_refuted": all_refuted,
        "mitre_grounded_count": grounded,
        "total": len(findings),
    }


def _compute_synthesizer_verdict(
    triage_report: dict,
    falsifier_result: Optional[dict],
    scanner_findings: Optional[dict],
    heterogeneity: dict,
) -> dict:
    """
    Non-LLM synthesizer (τ=0).
    Applies deterministic rules to produce final verdict.

    This is the key contribution of the orchestrator:
    a rule-based synthesizer has NO model family → τ=0 by definition.
    """
    verdict = triage_report.get("verdict", "INCONCLUSIVE")
    confidence = triage_report.get("confidence", 0.0)
    triage_report.get("severity", "none")
    scanner_flagged = False

    if scanner_findings:
        for scanner_name, result in scanner_findings.items():
            if isinstance(result, dict) and result.get("findings"):
                if len(result["findings"]) > 0:
                    scanner_flagged = True
                    break

    # Proof-stage summary — used to qualify rationale.
    proof = _proof_summary(triage_report)

    # Override: if ALL LLM findings were REFUTED by static analysis and
    # scanners also found nothing → downgrade to BENIGN (evidence absent).
    if proof["all_refuted"] and not scanner_flagged and verdict == "MALICIOUS":
        final = "INCONCLUSIVE"
        rationale = (
            "All triage findings REFUTED by proof stage (evidence strings absent from file) "
            "and no scanner corroboration — manual review recommended"
        )
        return {
            "final_verdict": final,
            "rationale": rationale,
            "proof_summary": proof,
            "heterogeneity_check": heterogeneity,
        }

    # Rule: scanner + triage agree on MALICIOUS → accept
    if verdict == "MALICIOUS" and confidence >= 0.85 and scanner_flagged:
        final = "MALICIOUS"
        rationale = "Scanner-triage consensus: both flag malicious indicators at high confidence"
        if proof["confirmed"] > 0:
            rationale += f" ({proof['confirmed']} finding(s) CONFIRMED by proof stage)"

    # Rule: scanner + triage agree on BENIGN → accept
    elif verdict == "BENIGN" and confidence >= 0.85 and not scanner_flagged:
        final = "BENIGN"
        rationale = "Scanner-triage consensus: no threats detected by either"

    # Rule: falsifier survived → accept triage verdict
    elif falsifier_result and falsifier_result.get("status") == "SURVIVED":
        final = verdict
        rationale = f"Triage survived adversarial review by {heterogeneity['auditor_family']} "

        if heterogeneity["heterogeneity_mandate_met"]:
            rationale += "(heterogeneous auditor — high confidence in result)"
        else:
            rationale += "(WARNING: same-family auditor — kinship lock risk per Shehata & Li 2026)"

    # Rule: falsifier falsified but triage confidence still high → flag
    elif falsifier_result and falsifier_result.get("status") == "FALSIFIED":
        if confidence >= 0.80:
            final = "SUSPICIOUS"
            rationale = "Triage confident but heterogeneous auditor found weaknesses"
        else:
            final = "INCONCLUSIVE"
            rationale = "Triage disputed by heterogeneous auditor — manual review recommended"

    # Rule: no falsifier, low confidence → flag
    elif confidence < FALSIFIER_TRIGGER_CONFIDENCE:
        final = "INCONCLUSIVE"
        rationale = "Low confidence without adversarial review"

    # Fallback
    else:
        final = verdict if verdict in ("MALICIOUS", "BENIGN") else "SUSPICIOUS"
        rationale = "Default to triage verdict (no contradictory evidence)"

    return {
        "final_verdict": final,
        "rationale": rationale,
        "proof_summary": proof,
        "heterogeneity_check": heterogeneity,
    }


def orchestrate(
    candidate_path: str,
    scanner_findings: Optional[dict] = None,
    falsifier_provider: str = "falsifier",
    max_iterations: int = MAX_CORRECTION_ITERATIONS,
) -> dict:
    """
    Run the full heterogeneous orchestration pipeline.

    Args:
        candidate_path: Path to the file to triage
        scanner_findings: Pre-computed scanner results (if None, scanners are run)
        falsifier_provider: Provider for the adversarial reviewer
                           MUST be architecturally different from the triage model
        max_iterations: Max correction cycles (2 per Shehata & Li 2026)

    Returns:
        OrchestrationReport with final verdict, rationale, and full audit trail
    """
    from execution_logger import get_logger
    audit = get_logger("logs/audit_trail.db")

    start_time = time.time()
    candidate = Path(candidate_path)

    # Stable run_id for this orchestration: ties scanner runs + triage + falsifier
    # + synthesizer together so judges can trace a verdict to its decision chain.
    import uuid
    run_id = f"orch_{uuid.uuid4().hex[:12]}"
    logger.info(f"Starting orchestration run_id={run_id} for {candidate_path}")

    if not candidate.exists():
        return {
            "final_verdict": "ERROR",
            "rationale": f"File not found: {candidate_path}",
            "_meta": {"duration_seconds": 0, "error": "file_not_found"},
        }

    # ── Phase 1: Run scanners (if not provided) ──────────────────────────
    scanner_start = time.time()
    if scanner_findings is None:
        try:
            from mcp_tools import run_all_scanners
            scanner_findings = run_all_scanners(str(candidate))
        except Exception as e:
            logger.warning(f"Scanner run failed: {e}, continuing without")
            scanner_findings = {}
    scanner_duration = time.time() - scanner_start

    # Log the scanner sweep as its own audit row so a run trace shows every
    # stage (agent_id="scanner"), not just the final synthesizer route.
    _scan_summary = _summarize_scanners(scanner_findings)
    audit.log("scanner_sweep", {"candidate": str(candidate)},
              {"verdict": "FLAGGED" if _scan_summary["total_findings"] else "CLEAN",
               "total_findings": _scan_summary["total_findings"],
               "scanners_fired": _scan_summary["scanners"]},
              scanner_duration * 1000, run_id=run_id, agent_id="scanner")

    # ── Phase 2: MR. Robot triage (propagator, Nemotron) ─────────────────
    triage_start = time.time()
    from agents.mr_robot.triage import triage
    triage_report = triage(
        str(candidate),
        findings=scanner_findings,
        json_output=True,
    )
    triage_duration = time.time() - triage_start

    if not isinstance(triage_report, dict):
        return {
            "final_verdict": "ERROR",
            "rationale": "Triage agent failed to produce structured output",
            "triage_raw": str(triage_report)[:500],
            "_meta": {"duration_seconds": time.time() - start_time},
        }

    verdict = triage_report.get("verdict", "INCONCLUSIVE")
    confidence = triage_report.get("confidence", 0.0)
    triage_model = triage_report.get("_meta", {}).get("model", "unknown")

    # Log the propagator (MR. Robot triage) call as its own audit row.
    audit.log("triage", {"candidate": str(candidate)},
              {"verdict": verdict, "confidence": confidence,
               "severity": triage_report.get("severity"), "model": triage_model},
              triage_duration * 1000, run_id=run_id, agent_id="mr_robot")

    # ── Phase 3: Decision routing ────────────────────────────────────────
    falsifier_result = None
    correction_history = []
    heterogeneity = {"propagator_family": _detect_family(triage_model),
                     "auditor_family": "none",
                     "architectural_distance": 0.0,
                     "kinship_lock_risk": "N/A",
                     "heterogeneity_mandate_met": False}

    # Rule: HIGH confidence + clear verdict → skip falsifier
    # Override: MR_ROBOT_FORCE_FALSIFIER=1 forces the falsifier for demo/audit mode
    force_falsifier = os.getenv("MR_ROBOT_FORCE_FALSIFIER", "0") == "1"
    route_start = time.time()
    if not force_falsifier and confidence >= HIGH_CONFIDENCE_STRAIGHT_TO_VERDICT and verdict in ("MALICIOUS", "BENIGN"):
        logger.info(f"High confidence ({confidence:.2f}), bypassing falsifier for {verdict}")
        route_duration_ms = (time.time() - route_start) * 1000
        audit.log("orchestrator_route", {"candidate": str(candidate)},
                  {"route": "direct", "verdict": verdict, "confidence": confidence,
                   "rule": "HIGH_CONFIDENCE_STRAIGHT_TO_VERDICT"},
                  route_duration_ms, run_id=run_id, agent_id="synthesizer")

    # Rule: everything else → falsifier with heterogeneous model
    else:
        logger.info(f"Routing to falsifier (confidence={confidence:.2f}, verdict={verdict})")

        # Import and configure the falsifier with a DIFFERENT model family
        from triage_falsifier import TriageFalsifier

        # Force DeepSeek (architecturally far from Nemotron)
        falsifier = TriageFalsifier(falsifier_provider)

        for iteration in range(max_iterations):
            falsifier_start = time.time()
            falsifier_result = falsifier.falsify(
                triage_report, str(candidate), scanner_findings
            )
            falsifier_duration_ms = (time.time() - falsifier_start) * 1000

            f_status = falsifier_result.get("status", "ERROR")
            f_model = falsifier_result.get("_meta", {}).get("model", "unknown")

            # Compute heterogeneity metrics
            heterogeneity = _check_heterogeneity(triage_model, f_model)

            # Log the falsifier (auditor) call as its own audit row, capturing the
            # heterogeneity diagnostics (ΔA + kinship-lock flag) per SANS req #8.
            audit.log("falsifier",
                      {"candidate": str(candidate), "iteration": iteration + 1,
                       "reviewing_verdict": verdict},
                      {"status": f_status, "model": f_model,
                       "architectural_distance": heterogeneity["architectural_distance"],
                       "kinship_lock_risk": heterogeneity["kinship_lock_risk"]},
                      falsifier_duration_ms, run_id=run_id, agent_id="falsifier")

            correction_history.append({
                "iteration": iteration + 1,
                "falsifier_status": f_status,
                "falsifier_model": f_model,
                "heterogeneity": heterogeneity,
            })

            if f_status == "SURVIVED":
                logger.info(f"Falsifier ({f_model}) SURVIVED — ΔA={heterogeneity['architectural_distance']}")
                break
            elif f_status == "FALSIFIED":
                logger.info(f"Falsifier ({f_model}) FALSIFIED — κ={heterogeneity['kinship_lock_risk']}")

                # If kinship lock detected, log warning
                if heterogeneity["kinship_lock_risk"] == "HIGH":
                    logger.warning(
                        "SAME-FAMILY FALSIFICATION DETECTED: per Shehata & Li (2026), "
                        "this may be sycophantic agreement rather than genuine correction. "
                        "Falsifier and Triage share the Nemotron family (ΔA≈0, τ high)."
                    )
                    audit.log("kinship_lock_warning",
                              {"candidate": str(candidate), "propagator": triage_model,
                               "auditor": f_model, "τ_risk": "HIGH"},
                              {"iteration": iteration + 1}, 0,
                              run_id=run_id, agent_id="falsifier")

                # Re-run triage with counter-argument
                from agents.mr_robot.triage import triage as retriage
                counter_context = {
                    "previous_verdict": verdict,
                    "falsifier_challenge": falsifier_result.get("summary", ""),
                    "falsifier_model": f_model,
                }
                prev_verdict = verdict
                retriage_start = time.time()
                triage_report = retriage(
                    str(candidate),
                    findings=scanner_findings,
                    context=counter_context,
                    json_output=True,
                )
                verdict = triage_report.get("verdict", verdict)
                confidence = triage_report.get("confidence", confidence)

                # Genuine self-correction record: the auditor challenged the verdict
                # and the propagator re-ran. Log the before/after so a verdict FLIP
                # is captured in the audit trail (not just a SURVIVED no-op).
                audit.log("self_correction",
                          {"candidate": str(candidate), "iteration": iteration + 1,
                           "falsifier_challenge": falsifier_result.get("summary", "")[:200]},
                          {"verdict_before": prev_verdict, "verdict_after": verdict,
                           "flipped": prev_verdict != verdict,
                           "confidence_after": confidence},
                          (time.time() - retriage_start) * 1000,
                          run_id=run_id, agent_id="mr_robot")
            else:
                # ERROR or INCONCLUSIVE from falsifier — stop iterating
                break

        audit.log("orchestrator_route", {"candidate": str(candidate)},
                  {"route": "falsifier", "iterations": len(correction_history),
                   "verdict": triage_report.get("verdict", "UNKNOWN"),
                   "confidence": triage_report.get("confidence", 0.0),
                   "final_status": falsifier_result.get("status", "N/A") if falsifier_result else "N/A"},
                  (time.time() - route_start) * 1000,
                  run_id=run_id, agent_id="synthesizer")

    # ── Phase 4: Synthesizer — non-LLM, τ=0 ──────────────────────────────
    synthesizer_result = _compute_synthesizer_verdict(
        triage_report, falsifier_result, scanner_findings, heterogeneity
    )

    total_duration = time.time() - start_time

    # ── Assemble final report ────────────────────────────────────────────
    return {
        "final_verdict": synthesizer_result["final_verdict"],
        "rationale": synthesizer_result["rationale"],
        "triage_report": triage_report,
        "falsifier_result": falsifier_result,
        "correction_history": correction_history,
        "scanner_findings_summary": _summarize_scanners(scanner_findings),
        "_meta": {
            "orchestrator_version": "1.0.0",
            "propagator_model": triage_model,
            "propagator_family": _detect_family(triage_model),
            "auditor_model": falsifier_result.get("_meta", {}).get("model", "none") if falsifier_result else "none",
            "auditor_family": heterogeneity["auditor_family"],
            "synthesizer_type": "rule-based (τ=0, non-LLM)",
            "heterogeneity_mandate": "Shehata & Li (2026), arXiv:2604.27274",
            "kinship_lock_risk": heterogeneity["kinship_lock_risk"],
            "candidate": str(candidate),
            "duration_seconds": round(total_duration, 2),
            "scanner_duration": round(scanner_duration, 2),
            "triage_duration": round(triage_duration, 2),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    }


def _summarize_scanners(scanner_findings: Optional[dict]) -> dict:
    """Compact scanner summary for the final report."""
    if not scanner_findings:
        return {"total_findings": 0, "scanners": {}}
    summary = {"total_findings": 0, "scanners": {}}
    for name, result in scanner_findings.items():
        if isinstance(result, dict):
            n = len(result.get("findings", [])) if "findings" in result else 0
            summary["scanners"][name] = n
            summary["total_findings"] += n
    return summary


def trace_run(run_id: Optional[str] = None, db_path: str = "logs/audit_trail.db") -> dict:
    """Reconstruct the full decision chain for an orchestration run.

    Returns the ordered audit rows for a single run_id (scanner → triage →
    falsifier → self_correction → synthesizer route) so a judge can trace a
    verdict back to every tool call that produced it (SANS requirement #8).
    With run_id=None, the most recent orchestration run is used.
    """
    from execution_logger import get_logger
    audit = get_logger(db_path)

    if run_id is None:
        recent = audit.query(limit=500)
        orch = [r for r in recent if str(r.get("run_id", "")).startswith("orch_")]
        if not orch:
            return {"run_id": None, "step_count": 0, "steps": [],
                    "error": "no orchestration runs found in audit trail"}
        run_id = orch[0]["run_id"]

    rows = audit.get_run(run_id)
    steps = []
    for r in rows:
        out = r.get("output_json")
        try:
            out = json.loads(out) if isinstance(out, str) else out
        except (ValueError, TypeError):
            pass
        steps.append({
            "agent": r.get("agent_id"),
            "tool": r.get("tool_name"),
            "verdict": r.get("verdict"),
            "duration_ms": r.get("duration_ms"),
            "output": out,
        })
    return {"run_id": run_id, "step_count": len(steps), "steps": steps}


# ── CLI entry point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    if len(sys.argv) < 2:
        print("Usage: python triage_orchestrator.py <candidate_path> [--provider falsifier|nvidia-nim|openrouter|ollama-cloud]")
        print("       python triage_orchestrator.py --trace [run_id]   # show a run's full decision chain")
        print("       python triage_orchestrator.py --last             # trace the most recent run")
        sys.exit(1)

    # Trace mode: reconstruct a run's audit chain (SANS req #8) instead of triaging.
    if sys.argv[1] in ("--trace", "--last"):
        rid = sys.argv[2] if (sys.argv[1] == "--trace" and len(sys.argv) > 2) else None
        print(json.dumps(trace_run(rid), indent=2, default=str))
        sys.exit(0)

    path = sys.argv[1]
    provider = "falsifier"
    for i, arg in enumerate(sys.argv):
        if arg == "--provider" and i + 1 < len(sys.argv):
            provider = sys.argv[i + 1]

    report = orchestrate(path, falsifier_provider=provider)
    print(json.dumps(report, indent=2, default=str))
