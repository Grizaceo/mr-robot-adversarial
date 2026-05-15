#!/usr/bin/env python3
"""
MCP Tools — Shared functions for FIND EVIL! MCP Server

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

CYBERSEC_LAB = Path(os.getenv("CYBERSEC_LAB", str(Path.home() / ".hermes" / "workspace" / "cybersecurity-lab")))
SCANNERS_DIR = CYBERSEC_LAB / "scanners"
MR_ROBOT = Path(__file__).parent / "agents" / "mr_robot" / "triage.py"
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
audit = get_logger("logs/audit_trail.db")


# ── Scanner Wrapper ──────────────────────────────────────────────────────────

def run_all_scanners(filepath: str, timeout: int = 30) -> dict[str, dict]:
    """Run all 4 scanners on a file. Returns {scanner_name: result}."""
    return {
        "skill_scanner": _run_scanner("skill_scanner", [filepath], timeout),
        "ioc_scanner": _run_scanner("ioc_scanner", [filepath], timeout),
        "yara": _run_scanner("scan_yara", [filepath], timeout),
        "secrets_detector": _run_scanner("secrets_detector", [filepath], timeout),
    }


def _run_scanner(scanner_name: str, args: list[str], timeout: int = 30) -> dict:
    """Run a single scanner CLI and return parsed JSON result."""
    script = SCANNERS_DIR / f"{scanner_name}.py"
    if not script.exists():
        return {"error": f"Scanner not found: {script}", "findings": []}

    json_out = LOG_DIR / f"scanner_{scanner_name}_{int(time.time())}.json"
    cmd = [sys.executable, str(script)] + args + ["--json", str(json_out)]

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       cwd=str(Path(__file__).parent))

        if json_out.exists():
            try:
                data = json.loads(json_out.read_text())
                if isinstance(data, list):
                    return {"findings": data, "raw": data}
                return data
            except json.JSONDecodeError:
                return {"error": f"Invalid JSON from {scanner_name}"}
        else:
            return {"error": f"No output from {scanner_name}"}

    except subprocess.TimeoutExpired:
        return {"error": f"{scanner_name} timed out after {timeout}s", "findings": []}
    except Exception as e:
        return {"error": f"{scanner_name} failed: {e}", "findings": []}
    finally:
        if json_out.exists():
            json_out.unlink(missing_ok=True)


# ── Agent Runner ──────────────────────────────────────────────

def run_triage_agent(filepath: str, scanner_results: Optional[dict] = None,
                     context: Optional[dict] = None, timeout: int = 120) -> dict:
    """Run MR. Robot triage agent as a subprocess. Returns triage report dict."""
    repo_root = Path(__file__).parent

    findings_file = LOG_DIR / f"findings_{int(time.time())}.json"
    if scanner_results:
        findings_file.write_text(json.dumps(scanner_results, default=str))

    context_file = None
    if context:
        context_file = LOG_DIR / f"context_{int(time.time())}.json"
        context_file.write_text(json.dumps(context))

    cmd = [sys.executable, str(MR_ROBOT), filepath,
           "--findings", str(findings_file), "--json"]
    if context_file:
        cmd.extend(["--context", str(context_file)])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout, cwd=str(repo_root))
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
                        max_iterations: int = 1) -> dict:
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
        report = run_triage_agent(filepath, scanner_results)
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
    """Aggregate results from multiple scanners into summary counts."""
    total = critical = high = medium = low = 0
    for scanner_name, result in results.items():
        if "error" in result:
            continue
        findings = result.get("findings", [])
        if not isinstance(findings, list):
            continue
        total += len(findings)
        for f in findings:
            sev = str(f.get("severity", "")).upper()
            if sev == "CRITICAL":
                critical += 1
            elif sev == "HIGH":
                high += 1
            elif sev == "MEDIUM":
                medium += 1
            else:
                low += 1
    # Also check by_severity from skill_scanner
    if "skill_scanner" in results and "by_severity" in results["skill_scanner"]:
        bs = results["skill_scanner"]["by_severity"]
        critical = max(critical, bs.get("CRITICAL", 0))
        high = max(high, bs.get("HIGH", 0))
        medium = max(medium, bs.get("MEDIUM", 0))
        low = max(low, bs.get("INFO", 0))

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
