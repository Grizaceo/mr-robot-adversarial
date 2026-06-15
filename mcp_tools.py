#!/usr/bin/env python3
"""
MCP Tools — Shared functions for MR. Robot MCP Server

Extracted from mcp_server.py to reduce duplication between tools.
"""

import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from execution_logger import get_logger

logger = logging.getLogger("mcp-tools")

# ── Configuration ─────────────────────────────────────────────────────────────

# Scanner resolution: prefer the bundled `scanners/` (works on a fresh clone).
# Honor CYBERSEC_LAB/scanners only if it actually exists AND has the expected scripts.
# This prevents the "fresh clone classifies a bind-shell as BENIGN" fail-open
# reported in the SANS FIND EVIL! pre-submission audit.
_BUNDLED_SCANNERS = Path(__file__).parent / "scanners"
_CYBERSEC_LAB_SCANNERS = Path(os.getenv("CYBERSEC_LAB", str(Path.home() / ".hermes" / "workspace" / "cybersecurity-lab"))) / "scanners"
SCANNERS_DIR = _BUNDLED_SCANNERS if _BUNDLED_SCANNERS.is_dir() else _CYBERSEC_LAB_SCANNERS
# Backwards-compat alias for mcp_server.py and any external import.
# NOTE: prefer SCANNERS_DIR for the scanner dir; this is the parent lab path.
CYBERSEC_LAB = _CYBERSEC_LAB_SCANNERS.parent
MR_ROBOT = Path(__file__).parent / "agents" / "mr_robot" / "triage.py"
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
audit = get_logger("logs/audit_trail.db")
MAX_INPUT_BYTES = int(os.getenv("MR_ROBOT_MAX_INPUT_BYTES", str(5 * 1024 * 1024)))


def _allowed_roots() -> list[Path]:
    raw = os.getenv("MR_ROBOT_ALLOWED_ROOTS")
    if raw:
        return [Path(p).expanduser().resolve() for p in raw.split(os.pathsep) if p.strip()]
    return [Path(__file__).parent.resolve(), _CYBERSEC_LAB_SCANNERS.parent.resolve()]


def validate_target_file(filepath: str) -> tuple[bool, dict]:
    target = Path(filepath).expanduser()
    try:
        resolved = target.resolve(strict=False)
    except Exception as e:
        return False, {"error": "invalid_path", "detail": str(e), "filepath": filepath}

    if not target.exists():
        return False, {"error": "file_not_found", "filepath": filepath}
    if target.is_symlink():
        return False, {"error": "symlink_not_allowed", "filepath": filepath}
    if not target.is_file():
        return False, {"error": "not_a_file", "filepath": filepath}
    if not os.access(target, os.R_OK):
        return False, {"error": "file_not_readable", "filepath": filepath}

    allowed_roots = _allowed_roots()
    if not any(root == resolved or root in resolved.parents for root in allowed_roots):
        return False, {
            "error": "path_outside_allowed_roots",
            "filepath": filepath,
            "resolved_path": str(resolved),
            "allowed_roots": [str(p) for p in allowed_roots],
        }

    size = target.stat().st_size
    if size > MAX_INPUT_BYTES:
        return False, {
            "error": "file_too_large",
            "filepath": filepath,
            "resolved_path": str(resolved),
            "size_bytes": size,
            "max_bytes": MAX_INPUT_BYTES,
        }

    return True, {"resolved_path": str(resolved), "size_bytes": size}


# ── Scanner Wrapper ──────────────────────────────────────────────────────────

def run_all_scanners(filepath: str, timeout: int = 30) -> dict[str, dict]:
    """Run all 4 scanners on a file. Returns {scanner_name: result}."""
    ok, payload = validate_target_file(filepath)
    if not ok:
        return {"validation": payload}

    filepath = payload["resolved_path"]
    return {
        "skill_scanner": _run_scanner("skill_scanner", [filepath], timeout),
        "ioc_scanner": _run_scanner("ioc_scanner", [filepath], timeout),
        "yara": _run_scanner("scan_yara", [filepath], timeout),
        "secrets_detector": _run_scanner("secrets_detector", [filepath], timeout),
    }


def _run_scanner(scanner_name: str, args: list[str], timeout: int = 30) -> dict:
    """Run a single scanner and return its findings.

    Uses direct Python import (not subprocess) — the previous subprocess-based
    approach was broken in fresh-clone contexts because the scanners had no
    `if __name__` CLI block. Direct import is the architecturally honest path:
    it can't drift, it surfaces real Python errors, and it preserves the
    evidence-integrity promise that the LLM cannot execute shell commands
    on the candidate file.

    Each scanner is invoked with a single positional arg (the file path).
    On any exception, we return a dict with `error: scanner_failed` plus the
    last 400 chars of the traceback. The aggregator then maps that to the
    fail-closed ERROR verdict (see `aggregate_scanner_results`).
    """
    filepath = args[0] if args else None
    if not filepath:
        return {"error": "no_target_file", "scanner": scanner_name, "findings": []}

    try:
        if scanner_name == "skill_scanner":
            from scanners.skill_scanner import scan_file as _scan
            from pathlib import Path as _P
            findings = _scan(_P(filepath))
            return {
                "findings": [
                    {
                        "rule_id": getattr(f, "rule_id", "?"),
                        "name": getattr(f, "name", "?"),
                        "severity": getattr(f, "severity", "MEDIUM"),
                        "filepath": str(getattr(f, "filepath", filepath)),
                        "line": getattr(f, "line", 0),
                        "matched_text": getattr(f, "matched_text", "")[:200],
                    }
                    for f in findings
                ],
                "scanner": scanner_name,
            }
        elif scanner_name == "ioc_scanner":
            from scanners.ioc_scanner import scan_file as _scan
            from pathlib import Path as _P
            findings = _scan(_P(filepath))
            return {"findings": findings if isinstance(findings, list) else [], "scanner": scanner_name}
        elif scanner_name in ("yara", "scan_yara"):
            from scanners.scan_yara import scan_file as _scan
            from pathlib import Path as _P
            res = _scan(_P(filepath))
            if isinstance(res, dict) and "findings" in res:
                return res
            return {"findings": res if isinstance(res, list) else [], "scanner": scanner_name}
        elif scanner_name == "secrets_detector":
            from scanners.secrets_detector import scan_file as _scan
            from pathlib import Path as _P
            findings = _scan(_P(filepath))
            return {
                "findings": [
                    {
                        "rule_id": getattr(f, "rule_id", "?"),
                        "name": getattr(f, "name", "?"),
                        "severity": getattr(f, "severity", "MEDIUM"),
                        "filepath": str(getattr(f, "filepath", filepath)),
                        "line": getattr(f, "line", 0),
                        "matched_text": getattr(f, "matched_text", "")[:200],
                    }
                    for f in findings
                ] if findings else [],
                "scanner": scanner_name,
            }
        else:
            return {"error": "scanner_not_found", "scanner": scanner_name, "findings": []}
    except Exception as e:
        import traceback
        return {
            "error": "scanner_failed",
            "scanner": scanner_name,
            "exception": type(e).__name__,
            "message": str(e)[:300],
            "stderr_tail": traceback.format_exc()[-400:],
            "findings": [],
        }


# ── Agent Runner ──────────────────────────────────────────────

def run_triage_agent(filepath: str, scanner_results: Optional[dict] = None,
                     context: Optional[dict] = None, scenario_id: str = "",
                     timeout: int = 120) -> dict:
    """Run MR. Robot triage agent as a subprocess. Returns triage report dict."""
    repo_root = Path(__file__).parent

    findings_file = LOG_DIR / f"findings_{int(time.time())}.json"
    if scanner_results:
        findings_file.write_text(json.dumps(scanner_results, default=str))

    context_file = None
    if context or scenario_id:
        if context is None:
            context = {}
        if scenario_id:
            context["scenario_id"] = scenario_id
        context_file = LOG_DIR / f"context_{int(time.time())}.json"
        context_file.write_text(json.dumps(context))

    cmd = [sys.executable, str(MR_ROBOT), filepath,
           "--findings", str(findings_file), "--json"]
    if context_file:
        cmd.extend(["--context", str(context_file)])

    # Pass API keys to subprocess
    env = os.environ.copy()

    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout, cwd=str(repo_root), env=env)
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
        return {
            "verdict": "ERROR", "confidence": 0.0, "severity": "none",
            "summary": f"MR. Robot failed: {result.stderr[:500]}",
            "findings": [], "recommended_actions": ["retry", "manual_review"],
        }
    except Exception as e:
        return {
            "verdict": "ERROR", "confidence": 0.0, "severity": "none",
            "summary": f"MR. Robot error: {e}",
            "findings": [], "recommended_actions": ["retry", "manual_review"],
        }
    finally:
        findings_file.unlink(missing_ok=True)
        if context_file:
            context_file.unlink(missing_ok=True)


def run_falsifier_loop(filepath: str, scanner_results: dict,
                        confidence_threshold: float = 0.99,
                        max_iterations: int = 1,
                        scenario_id: str = "") -> dict:
    """Run triage + falsifier self-correction loop. Returns final report."""
    try:
        from triage_falsifier import run_self_correction_loop
        return run_self_correction_loop(
            filepath, scanner_findings=scanner_results,
            confidence_threshold=confidence_threshold,
            max_iterations=max_iterations,
        )
    except Exception as e:
        logger.error(f"Falsifier loop failed: {e}, falling back to triage only")
        report = run_triage_agent(filepath, scanner_results, scenario_id=scenario_id)
        report["_correction"] = {"error": str(e), "iterations": 0}
        return report


# ── Audit Helper ──────────────────────────────────────────────

def log_tool(tool_name: str, args: dict, result: str, start_time: float):
    """Log a tool execution to the audit trail."""
    duration_ms = (time.perf_counter() - start_time) * 1000
    try:
        output = json.loads(result) if result.strip().startswith(("{", "[")) else {"text": result[:1000]}
    except Exception:
        output = {"text": result[:1000]}
    audit.log(tool_name=tool_name, input_data=args, output_data=output,
              duration_ms=duration_ms)


# ── Verdict Helper ────────────────────────────────────────────

def verdict_to_severity(verdict: str) -> str:
    """Map verdict string to severity level."""
    return {"MALICIOUS": "critical", "SUSPICIOUS": "high"}.get(verdict, "none")


def aggregate_scanner_results(results: dict[str, dict]) -> dict:
    """Aggregate results from multiple scanners into summary counts.

    Fail-closed: if ANY scanner reported `scanner_not_found` (or any other error),
    the aggregate verdict is ERROR — never BENIGN. This is the explicit fix for
    the "fresh clone classifies a bind-shell as BENIGN" finding from the
    SANS FIND EVIL! pre-submission audit.
    """
    total = critical = high = medium = low = 0
    missing_scanners = []
    errored_scanners = []

    def _finding_severity(f) -> str:
        # Findings can be dicts OR ScanFinding dataclass instances.
        if isinstance(f, dict):
            return str(f.get("severity", "")).upper()
        return str(getattr(f, "severity", "")).upper()

    for scanner_name, result in results.items():
        if not isinstance(result, dict):
            continue
        if result.get("error") == "scanner_not_found":
            missing_scanners.append(scanner_name)
            continue
        if "error" in result:
            errored_scanners.append({"scanner": scanner_name, "error": result["error"]})
            continue
        findings = result.get("findings", [])
        if not isinstance(findings, list):
            continue
        total += len(findings)
        for f in findings:
            sev = _finding_severity(f)
            if sev == "CRITICAL":
                critical += 1
            elif sev == "HIGH":
                high += 1
            elif sev == "MEDIUM":
                medium += 1
            else:
                low += 1
    # Also check by_severity from skill_scanner
    if "skill_scanner" in results and isinstance(results["skill_scanner"], dict) and "by_severity" in results["skill_scanner"]:
        bs = results["skill_scanner"]["by_severity"]
        critical = max(critical, bs.get("CRITICAL", 0))
        high = max(high, bs.get("HIGH", 0))
        medium = max(medium, bs.get("MEDIUM", 0))
        low = max(low, bs.get("INFO", 0))

    if missing_scanners or errored_scanners:
        # Fail-closed: do not silently mark BENIGN when scanners are missing.
        return {
            "total_findings": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "overall_verdict": "ERROR",
            "error": "scanner_unavailable",
            "missing_scanners": missing_scanners,
            "errored_scanners": errored_scanners,
            "message": (
                f"Cannot produce a verdict: {len(missing_scanners)} scanner(s) missing, "
                f"{len(errored_scanners)} errored. Defaulting to ERROR (not BENIGN) "
                "to avoid a fail-open false negative."
            ),
        }

    if critical > 0:
        verdict = "MALICIOUS"
    elif high > 0:
        verdict = "SUSPICIOUS"
    elif total > 0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BENIGN"

    return {"total_findings": total, "critical": critical, "high": high,
            "medium": medium, "low": low, "overall_verdict": verdict}
