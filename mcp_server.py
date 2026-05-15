#!/usr/bin/env python3
"""
MCP Server — MR. Robot Adversarial

Exposes cybersecurity-lab scanners + MR. Robot triage as MCP tools
using the Model Context Protocol (stdio transport).

Tools:
    scan_file          — Run all scanners (skill, ioc, yara, secrets) on a file
    triage_artifact    — Run MR. Robot triage on a file with scanner context
    falsify_triage     — Triage + Falsifier self-correction loop
    get_baseline       — Retrieve baseline results for a scenario
    health             — Check all components are operational

Usage:
    python mcp_server.py
"""

import json
import time
import logging
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from mcp_tools import (
    CYBERSEC_LAB,
    SCANNERS_DIR,
    aggregate_scanner_results,
    log_tool,
    run_all_scanners,
    run_falsifier_loop,
    run_triage_agent,
    validate_target_file,
    verdict_to_severity,
)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("mcp-server")

# ── Pydantic Models ───────────────────────────────────────────────────────────

class ScanResult(BaseModel):
    file: str
    timestamp: str
    scanners: dict[str, Any]
    summary: dict[str, Any]
    overall_verdict: str
    severity: str = "none"

class TriageResult(BaseModel):
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
    scenario_id: str
    exists: bool
    data: dict[str, Any] = {}

class HealthResult(BaseModel):
    status: str
    components: dict[str, str]
    timestamp: str


# ── MCP Server ────────────────────────────────────────────────────────────────

mcp = FastMCP(name="mr-robot-mcp")


@mcp.tool()
def scan_file(filepath: str) -> str:
    """Run all cybersecurity scanners on a file."""
    start = time.perf_counter()
    logger.info(f"scan_file: {filepath}")

    ok, payload = validate_target_file(filepath)
    if not ok:
        return json.dumps(payload)

    filepath = payload["resolved_path"]
    results = run_all_scanners(filepath)
    summary = aggregate_scanner_results(results)
    verdict = summary["overall_verdict"]

    output = ScanResult(
        file=filepath,
        timestamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        scanners=results, summary=summary,
        overall_verdict=verdict,
        severity=verdict_to_severity(verdict),
    )

    result = output.model_dump_json(indent=2)
    log_tool("scan_file", {"filepath": filepath}, result, start)
    return result


@mcp.tool()
def triage_artifact(filepath: str, scenario_id: str = "") -> str:
    """Run MR. Robot triage on a file with full scanner context."""
    start = time.perf_counter()
    logger.info(f"triage_artifact: {filepath}")

    ok, payload = validate_target_file(filepath)
    if not ok:
        return json.dumps(payload)

    filepath = payload["resolved_path"]
    scanner_results = run_all_scanners(filepath)
    triage_data = run_triage_agent(filepath, scanner_results)

    output = TriageResult(
        verdict=triage_data.get("verdict", "ERROR"),
        confidence=triage_data.get("confidence", 0.0),
        severity=triage_data.get("severity", "none"),
        summary=triage_data.get("summary", ""),
        findings=triage_data.get("findings", []),
        recommended_actions=triage_data.get("recommended_actions", []),
        scanner_correlation=triage_data.get("scanner_correlation", ""),
        model_used=triage_data.get("_meta", {}).get("model", ""),
        duration_seconds=round(time.perf_counter() - start, 2),
    )

    result = output.model_dump_json(indent=2)
    log_tool("triage_artifact", {"filepath": filepath, "scenario_id": scenario_id}, result, start)
    return result


@mcp.tool()
def falsify_triage(filepath: str, scenario_id: str = "") -> str:
    """Run MR. Robot triage with Falsifier self-correction loop."""
    start = time.perf_counter()
    logger.info(f"falsify_triage: {filepath}")

    ok, payload = validate_target_file(filepath)
    if not ok:
        return json.dumps(payload)

    filepath = payload["resolved_path"]
    scanner_results = run_all_scanners(filepath)
    final_report = run_falsifier_loop(filepath, scanner_results)

    result = json.dumps(final_report, indent=2, default=str)
    log_tool("falsify_triage", {"filepath": filepath, "scenario_id": scenario_id}, result, start)
    return result


@mcp.tool()
def get_baseline(scenario_id: str) -> str:
    """Retrieve baseline results for a scenario."""
    start = time.perf_counter()
    logger.info(f"get_baseline: {scenario_id}")

    baselines_dir = CYBERSEC_LAB / "baselines"
    for search_dir in [baselines_dir, baselines_dir / "runtime"]:
        if search_dir.exists():
            matches = list(search_dir.glob(f"*{scenario_id}*.json"))
            if matches:
                data = json.loads(matches[0].read_text())
                output = BaselineResult(scenario_id=scenario_id, exists=True, data=data)
                result = output.model_dump_json(indent=2)
                log_tool("get_baseline", {"scenario_id": scenario_id}, result, start)
                return result

    output = BaselineResult(scenario_id=scenario_id, exists=False)
    result = output.model_dump_json(indent=2)
    log_tool("get_baseline", {"scenario_id": scenario_id}, result, start)
    return result


@mcp.tool()
def health() -> str:
    """Check health of all MCP server components."""
    start = time.perf_counter()
    components = {}

    components["cybersecurity_lab"] = "OK" if CYBERSEC_LAB.exists() else f"NOT FOUND: {CYBERSEC_LAB}"
    for scanner in ["skill_scanner", "ioc_scanner", "scan_yara", "secrets_detector"]:
        components[scanner] = "OK" if (SCANNERS_DIR / f"{scanner}.py").exists() else "MISSING"
    components["mr_robot"] = "OK" if (Path(__file__).parent / "agents" / "mr_robot" / "triage.py").exists() else "MISSING"
    components["yara_rules"] = "OK" if (SCANNERS_DIR / "davi_malware_rules.yar").exists() else "MISSING"

    all_ok = all(v == "OK" for v in components.values())
    output = HealthResult(status="healthy" if all_ok else "degraded",
                          components=components,
                          timestamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat())
    result = output.model_dump_json(indent=2)
    log_tool("health", {}, result, start)
    return result


if __name__ == "__main__":
    logger.info("Starting MR. Robot MCP Server (stdio)")
    mcp.run(transport="stdio")
