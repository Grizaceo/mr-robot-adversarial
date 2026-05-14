#!/usr/bin/env python3
"""
MCP Server — FIND EVIL! Hackathon

Exposes cybersecurity-lab scanners + MR. Robot triage as MCP tools
using the Model Context Protocol (stdio transport).

Tools:
    scan_file          — Run all scanners (skill, ioc, yara, secrets) on a file
    triage_artifact    — Run MR. Robot triage on a file with scanner context
    get_baseline       — Retrieve baseline results for a scenario
    health             — Check all components are operational

Usage:
    python -m mcp_server
    # Or via MCP client config:
    # {"mcpServers": {"find-evil": {"command": "python", "args": ["-m", "mcp_server"]}}}
"""

import os
import sys
import json
import subprocess
import time
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

# ── Configuration ─────────────────────────────────────────────────────────────

CYBERSEC_LAB = Path(os.getenv("CYBERSEC_LAB", "/home/gris/.hermes/workspace/cybersecurity-lab"))
SCANNERS_DIR = CYBERSEC_LAB / "scanners"
MR_ROBOT = Path(__file__).parent / "agents" / "mr_robot" / "triage.py"
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "mcp_server.log"),
        logging.StreamHandler(sys.stderr),
    ],
)
logger = logging.getLogger("mcp-server")

# ── Pydantic Models ───────────────────────────────────────────────────────────

class ScanResult(BaseModel):
    """Result from running all scanners on a file."""
    file: str
    timestamp: str
    scanners: dict[str, Any]
    summary: dict[str, Any] = Field(description="Counts: total_findings, critical, high, medium, low, overall_verdict")
    overall_verdict: str = Field(description="MALICIOUS | SUSPICIOUS | BENIGN | ERROR")


class TriageResult(BaseModel):
    """Result from MR. Robot triage."""
    verdict: str
    confidence: float
    severity: str
    summary: str
    findings: list[dict[str, Any]] = []
    recommended_actions: list[str] = []
    scanner_correlation: str = ""
    model_used: str = ""
    duration_seconds: float = 0.0


class BaselineResult(BaseModel):
    """Baseline data for a scenario."""
    scenario_id: str
    exists: bool
    data: dict[str, Any] = {}


class HealthResult(BaseModel):
    """Health check result."""
    status: str
    components: dict[str, str]
    timestamp: str


# ── Scanner Wrappers ──────────────────────────────────────────────────────────

def _run_scanner(scanner_name: str, args: list[str], timeout: int = 30) -> dict:
    """Run a scanner CLI and return parsed JSON result."""
    script = SCANNERS_DIR / f"{scanner_name}.py"
    if not script.exists():
        return {"error": f"Scanner not found: {script}", "findings": []}

    json_out = LOG_DIR / f"scanner_{scanner_name}_{int(time.time())}.json"
    cmd = [sys.executable, str(script)] + args + ["--json", str(json_out)]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(Path(__file__).parent),  # repo root, where LOG_DIR lives
        )

        if json_out.exists():
            try:
                data = json.loads(json_out.read_text())
                # Normalize: ensure findings key exists
                if isinstance(data, list):
                    return {"findings": data, "raw": data}
                return data
            except json.JSONDecodeError:
                return {"error": f"Invalid JSON from {scanner_name}", "stdout": result.stdout[:500]}
        else:
            return {"error": f"No output from {scanner_name}", "stdout": result.stdout[:500], "stderr": result.stderr[:500]}

    except subprocess.TimeoutExpired:
        return {"error": f"{scanner_name} timed out after {timeout}s", "findings": []}
    except Exception as e:
        return {"error": f"{scanner_name} failed: {e}", "findings": []}
    finally:
        # Cleanup temp file
        if json_out.exists():
            json_out.unlink(missing_ok=True)


def _aggregate_scanner_results(results: dict[str, dict]) -> dict:
    """Aggregate results from multiple scanners into a summary."""
    total = 0
    critical = 0
    high = 0
    medium = 0
    low = 0

    for scanner_name, result in results.items():
        if "error" in result:
            continue
        findings = result.get("findings", [])
        if not isinstance(findings, list):
            findings = []
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

    return {
        "total_findings": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
    }


# ── MCP Server ────────────────────────────────────────────────────────────────

mcp = FastMCP(
    name="find-evil-mcp",
    instructions=(
        "FIND EVIL! MCP Server — Cybersecurity incident response tools.\n"
        "Provides scanner wrappers (skill, ioc, yara, secrets) and MR. Robot triage agent.\n"
        "All tools are read-only and safe — no destructive actions."
    ),
)


@mcp.tool()
def scan_file(filepath: str) -> str:
    """
    Run all cybersecurity scanners on a file.

    Executes skill_scanner, ioc_scanner, yara, and secrets_detector
    on the target file and returns aggregated results.

    Args:
        filepath: Absolute path to the file to scan

    Returns:
        JSON string with scanner results, summary counts, and overall verdict
    """
    start = time.perf_counter()
    logger.info(f"scan_file: {filepath}")

    if not Path(filepath).exists():
        return json.dumps({"error": f"File not found: {filepath}"})

    results = {
        "skill_scanner": _run_scanner("skill_scanner", [filepath]),
        "ioc_scanner": _run_scanner("ioc_scanner", [filepath]),
        "yara": _run_scanner("scan_yara", [filepath]),
        "secrets_detector": _run_scanner("secrets_detector", [filepath]),
    }

    summary = _aggregate_scanner_results(results)

    # Determine overall verdict from counts
    if summary["critical"] > 0:
        verdict = "MALICIOUS"
    elif summary["high"] > 0:
        verdict = "SUSPICIOUS"
    elif summary["total_findings"] > 0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BENIGN"

    output = ScanResult(
        file=filepath,
        timestamp=datetime.now(timezone.utc).isoformat(),
        scanners=results,
        summary=summary,
        overall_verdict=verdict,
    )

    elapsed = time.perf_counter() - start
    logger.info(f"scan_file complete: {verdict} ({elapsed:.1f}s)")

    return output.model_dump_json(indent=2)


@mcp.tool()
def triage_artifact(filepath: str, scenario_id: str = "") -> str:
    """
    Run MR. Robot triage on a file with full scanner context.

    First runs all scanners, then sends findings to MR. Robot (Ollama Cloud)
    for AI-powered triage with MITRE ATT&CK mapping.

    Args:
        filepath: Absolute path to the file to triage
        scenario_id: Optional scenario identifier for context

    Returns:
        JSON string with triage report including verdict, confidence, severity,
        findings, MITRE mapping, and recommended actions
    """
    start = time.perf_counter()
    logger.info(f"triage_artifact: {filepath}")

    if not Path(filepath).exists():
        return json.dumps({"error": f"File not found: {filepath}"})

    # Step 1: Run all scanners
    scanner_results = {
        "skill_scanner": _run_scanner("skill_scanner", [filepath]),
        "ioc_scanner": _run_scanner("ioc_scanner", [filepath]),
        "yara": _run_scanner("scan_yara", [filepath]),
        "secrets_detector": _run_scanner("secrets_detector", [filepath]),
    }

    # Step 2: Write findings to temp file for MR. Robot
    findings_file = LOG_DIR / f"findings_{int(time.time())}.json"
    findings_file.write_text(json.dumps(scanner_results, default=str))

    context = {"scenario_id": scenario_id} if scenario_id else None
    context_file = None
    if context:
        context_file = LOG_DIR / f"context_{int(time.time())}.json"
        context_file.write_text(json.dumps(context))

    # Step 3: Run MR. Robot
    repo_root = Path(__file__).parent
    cmd = [
        sys.executable, str(MR_ROBOT),
        filepath,
        "--findings", str(findings_file),
        "--json",
    ]
    if context_file:
        cmd.extend(["--context", str(context_file)])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(repo_root),
        )

        if result.returncode == 0 and result.stdout.strip():
            triage_data = json.loads(result.stdout)
        else:
            triage_data = {
                "verdict": "ERROR",
                "confidence": 0.0,
                "severity": "none",
                "summary": f"MR. Robot failed: {result.stderr[:500]}",
                "findings": [],
                "recommended_actions": ["retry", "manual_review"],
            }

    except Exception as e:
        triage_data = {
            "verdict": "ERROR",
            "confidence": 0.0,
            "severity": "none",
            "summary": f"MR. Robot error: {e}",
            "findings": [],
            "recommended_actions": ["retry", "manual_review"],
        }
    finally:
        findings_file.unlink(missing_ok=True)
        if context_file:
            context_file.unlink(missing_ok=True)

    elapsed = time.perf_counter() - start

    output = TriageResult(
        verdict=triage_data.get("verdict", "ERROR"),
        confidence=triage_data.get("confidence", 0.0),
        severity=triage_data.get("severity", "none"),
        summary=triage_data.get("summary", ""),
        findings=triage_data.get("findings", []),
        recommended_actions=triage_data.get("recommended_actions", []),
        scanner_correlation=triage_data.get("scanner_correlation", ""),
        model_used=triage_data.get("_meta", {}).get("model", ""),
        duration_seconds=round(elapsed, 2),
    )

    logger.info(f"triage_artifact complete: {output.verdict} ({elapsed:.1f}s)")

    return output.model_dump_json(indent=2)


@mcp.tool()
def get_baseline(scenario_id: str) -> str:
    """
    Retrieve baseline results for a scenario.

    Looks up previously recorded baseline data for a given scenario
    from the cybersecurity-lab baselines directory.

    Args:
        scenario_id: Scenario identifier (e.g., "adversarial-bind-shell")

    Returns:
        JSON string with baseline data if found
    """
    logger.info(f"get_baseline: {scenario_id}")

    baselines_dir = CYBERSEC_LAB / "baselines"
    # Search for matching baseline files
    matches = list(baselines_dir.glob(f"*{scenario_id}*.json"))

    if matches:
        data = json.loads(matches[0].read_text())
        output = BaselineResult(scenario_id=scenario_id, exists=True, data=data)
    else:
        # Check runtime baselines
        runtime_dir = baselines_dir / "runtime"
        if runtime_dir.exists():
            matches = list(runtime_dir.glob(f"*{scenario_id}*.json"))
            if matches:
                data = json.loads(matches[0].read_text())
                output = BaselineResult(scenario_id=scenario_id, exists=True, data=data)
            else:
                output = BaselineResult(scenario_id=scenario_id, exists=False)
        else:
            output = BaselineResult(scenario_id=scenario_id, exists=False)

    return output.model_dump_json(indent=2)


@mcp.tool()
def health() -> str:
    """
    Check health of all MCP server components.

    Verifies that all scanners, MR. Robot, and the cybersecurity-lab
    directory are accessible and operational.

    Returns:
        JSON string with component status
    """
    components = {}

    # Check cybersecurity-lab directory
    if CYBERSEC_LAB.exists():
        components["cybersecurity_lab"] = "OK"
    else:
        components["cybersecurity_lab"] = f"NOT FOUND: {CYBERSEC_LAB}"

    # Check scanners
    for scanner in ["skill_scanner", "ioc_scanner", "scan_yara", "secrets_detector"]:
        script = SCANNERS_DIR / f"{scanner}.py"
        components[scanner] = "OK" if script.exists() else "MISSING"

    # Check MR. Robot
    components["mr_robot"] = "OK" if MR_ROBOT.exists() else "MISSING"

    # Check YARA rules
    yara_rules = SCANNERS_DIR / "davi_malware_rules.yar"
    components["yara_rules"] = "OK" if yara_rules.exists() else "MISSING"

    all_ok = all(v == "OK" for v in components.values())

    output = HealthResult(
        status="healthy" if all_ok else "degraded",
        components=components,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    return output.model_dump_json(indent=2)


# ── CLI Entry Point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Run via stdio transport (standard for MCP)
    logger.info("Starting FIND EVIL! MCP Server (stdio)")
    mcp.run(transport="stdio")
