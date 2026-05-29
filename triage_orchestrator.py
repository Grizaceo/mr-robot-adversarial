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
    for family_id, keywords in [
        ("nemotron", ["nemotron", "nvidia"]),
        ("deepseek", ["deepseek"]),
        ("llama", ["llama"]),
        ("mistral", ["mistral"]),
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

    same_family = (p_family == a_family == "nemotron")

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
    falsifier_provider: str = "deepseek",
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

    # ── Phase 3: Decision routing ────────────────────────────────────────
    falsifier_result = None
    correction_history = []
    heterogeneity = {"propagator_family": _detect_family(triage_model),
                     "auditor_family": "none",
                     "architectural_distance": 0.0,
                     "kinship_lock_risk": "N/A",
                     "heterogeneity_mandate_met": False}

    # Rule: HIGH confidence + clear verdict → skip falsifier
    if confidence >= HIGH_CONFIDENCE_STRAIGHT_TO_VERDICT and verdict in ("MALICIOUS", "BENIGN"):
        logger.info(f"High confidence ({confidence:.2f}), bypassing falsifier for {verdict}")
        audit.log("orchestrator_route", {"candidate": str(candidate)},
                  {"route": "direct", "verdict": verdict, "confidence": confidence}, 0)

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
            time.time() - falsifier_start

            f_status = falsifier_result.get("status", "ERROR")
            f_model = falsifier_result.get("_meta", {}).get("model", "unknown")

            # Compute heterogeneity metrics
            heterogeneity = _check_heterogeneity(triage_model, f_model)

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
                              {"iteration": iteration + 1}, 0)

                # Re-run triage with counter-argument
                from agents.mr_robot.triage import triage as retriage
                counter_context = {
                    "previous_verdict": verdict,
                    "falsifier_challenge": falsifier_result.get("summary", ""),
                    "falsifier_model": f_model,
                }
                triage_report = retriage(
                    str(candidate),
                    findings=scanner_findings,
                    context=counter_context,
                    json_output=True,
                )
                verdict = triage_report.get("verdict", verdict)
                confidence = triage_report.get("confidence", confidence)
            else:
                # ERROR or INCONCLUSIVE from falsifier — stop iterating
                break

        audit.log("orchestrator_route", {"candidate": str(candidate)},
                  {"route": "falsifier", "iterations": len(correction_history),
                   "final_status": falsifier_result.get("status", "N/A") if falsifier_result else "N/A"}, 0)

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


# ── CLI entry point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    if len(sys.argv) < 2:
        print("Usage: python triage_orchestrator.py <candidate_path> [--provider deepseek|ollama-cloud]")
        sys.exit(1)

    path = sys.argv[1]
    provider = "deepseek"
    for i, arg in enumerate(sys.argv):
        if arg == "--provider" and i + 1 < len(sys.argv):
            provider = sys.argv[i + 1]

    report = orchestrate(path, falsifier_provider=provider)
    print(json.dumps(report, indent=2, default=str))
