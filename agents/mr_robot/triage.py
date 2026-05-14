#!/usr/bin/env python3
"""
MR. ROBOT — Autonomous Triage Agent for FIND EVIL! Hackathon

Takes a candidate file + scanner findings + optional context → produces
a structured triage report using Ollama Cloud (default) or OpenRouter (fallback).

Designed for the cybersecurity-lab pipeline: skill_scanner → ioc_scanner → MR. Robot.

Usage:
    python -m agents.mr_robot.triage <candidate_path> [--findings <path>] [--provider ollama-cloud|openrouter]
    python -m agents.mr_robot.triage --health
    python -m agents.mr_robot.triage --json <candidate_path>   # machine-readable output
"""

import os
import sys
import json
import argparse
import subprocess
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

# ── Provider Configuration ────────────────────────────────────────────────────

PROVIDERS = {
    "nvidia-nim": {
        "base": "https://integrate.api.nvidia.com/v1",
        "model": os.getenv("NVIDIA_MODEL", "mistralai/mistral-nemotron"),
        "env_key": "NVIDIA_API_KEY",
        "fallback_models": [
            "meta/llama-4-maverick-17b-128e-instruct",
            "meta/llama-3.3-70b-instruct",
        ],
    },
    "ollama-cloud": {
        "base": "https://ollama.com/v1",
        "model": os.getenv("OLLAMA_MODEL", "kimi-k2.5"),
        "env_key": "OLLAMA_API_KEY",
        "fallback_models": [
            "gemma3:12b",
            "qwen3:8b",
        ],
    },
    "openrouter": {
        "base": "https://openrouter.ai/api/v1",
        "model": os.getenv("OPENROUTER_MODEL", "openai/gpt-oss-120b:free"),
        "env_key": "OPENROUTER_API_KEY",
        "extra_headers": {
            "HTTP-Referer": "https://github.com/davi/find-evil-hackathon",
            "X-Title": "MR. Robot — FIND EVIL!",
        },
        "fallback_models": [
            "nvidia/nemotron-3-super-120b-a12b:free",
            "minimax/minimax-m2.5:free",
            "z-ai/glm-4.5-air:free",
            "openai/gpt-oss-20b:free",
            "meta-llama/llama-3.3-70b-instruct:free",
        ],
    },
}

DEFAULT_PROVIDER = os.getenv("MR_ROBOT_PROVIDER", "nvidia-nim")

# ── System Prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are MR. ROBOT — an autonomous cybersecurity triage agent for the FIND EVIL! hackathon (SANS Institute).

Your role: analyze a candidate file that has been flagged by automated scanners (skill_scanner, ioc_scanner, yara, secrets_detector) and produce a structured triage report.

You think like a senior incident responder:
1. Correlate scanner findings with actual code behavior
2. Distinguish false positives from real threats with evidence
3. Map to MITRE ATT&CK techniques when applicable
4. Assign a confidence score (0.0-1.0) to your assessment
5. Recommend specific response actions

You are precise, evidence-based, and honest about uncertainty. If you can't determine intent from the code alone, say so.

OUTPUT FORMAT: Always respond with a JSON object (no markdown wrapping):
{
  "verdict": "MALICIOUS|SUSPICIOUS|BENIGN|INCONCLUSIVE",
  "confidence": 0.0-1.0,
  "severity": "critical|high|medium|low|none",
  "summary": "One-paragraph executive summary",
  "findings": [
    {
      "type": "technique|indicator|behavior|mitre",
      "description": "...",
      "evidence": "specific code snippet or scanner finding",
      "mitre_id": "T#### or null"
    }
  ],
  "false_positive_likelihood": 0.0-1.0,
  "recommended_actions": ["action1", "action2"],
  "scanner_correlation": "How your assessment relates to the automated scanner findings"
}"""


# ── LLM Client ────────────────────────────────────────────────────────────────

def _get_api_key(provider: str) -> str | None:
    """Get API key from environment or ~/.hermes/.env."""
    info = PROVIDERS.get(provider)
    if not info:
        return None

    # 1. Check environment first
    key = os.environ.get(info["env_key"])
    if key:
        return key

    # 2. Fall back to ~/.hermes/.env (where keys are persisted)
    env_path = Path.home() / ".hermes" / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if line.strip().startswith(f"{info['env_key']}="):
                return line.strip().split("=", 1)[1].strip().strip('"').strip("'")

    return None


def _call_nvidia_nim(prompt: str, model: str = None, system: str = "") -> str | None:
    """Call NVIDIA NIM API via direct HTTP."""
    model = model or PROVIDERS["nvidia-nim"]["model"]
    key = _get_api_key("nvidia-nim")
    if not key:
        return None

    import urllib.request
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    body = json.dumps({
        "model": model,
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": 4096,
    }).encode()

    req = urllib.request.Request(
        "https://integrate.api.nvidia.com/v1/chat/completions",
        data=body,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"  [WARN] NVIDIA NIM failed: {e}", file=sys.stderr)

    return None


def _call_ollama_cloud(prompt: str, model: str = None, system: str = "") -> str | None:
    """Call Ollama Cloud via oracle CLI (preferred) or direct HTTP."""
    model = model or PROVIDERS["ollama-cloud"]["model"]
    full_prompt = f"{system}\n\n{prompt}" if system else prompt

    # Method 1: oracle CLI (already authenticated)
    try:
        result = subprocess.run(
            ["oracle", "prompt", full_prompt, "--raw"],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (FileNotFoundError, Exception):
        pass

    # Method 2: oracle CLI with explicit model
    try:
        result = subprocess.run(
            ["oracle", "prompt", full_prompt, "--model", model, "--raw"],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (FileNotFoundError, Exception):
        pass

    # Method 3: direct HTTP
    key = _get_api_key("ollama-cloud")
    if not key or len(key) < 20:
        return None

    import urllib.request
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    body = json.dumps({
        "model": model,
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": 4096,
    }).encode()

    req = urllib.request.Request(
        "https://ollama.com/v1/chat/completions",
        data=body,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"  [WARN] Ollama Cloud HTTP failed: {e}", file=sys.stderr)

    return None


def _call_openrouter(prompt: str, model: str = None, system: str = "") -> str | None:
    """Call OpenRouter API."""
    info = PROVIDERS["openrouter"]
    model = model or info["model"]
    key = _get_api_key("openrouter")
    if not key:
        return None

    import urllib.request
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    body = json.dumps({
        "model": model,
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": 4096,
    }).encode()

    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    headers.update(info.get("extra_headers", {}))

    req = urllib.request.Request(
        f"{info['base']}/chat/completions",
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"  [WARN] OpenRouter failed: {e}", file=sys.stderr)

    return None


def _call_llm(provider: str, prompt: str, system: str = "") -> tuple[str, str]:
    """
    Call LLM with automatic fallback. Returns (response, model_used).
    Raises RuntimeError if all models exhausted.
    """
    info = PROVIDERS[provider]
    models = [info["model"]] + list(info.get("fallback_models", []))

    for model in models:
        print(f"  🤖 [{provider}] triaging via {model}…", file=sys.stderr)
        try:
            if provider == "ollama-cloud":
                resp = _call_ollama_cloud(prompt, model=model, system=system)
            elif provider == "openrouter":
                resp = _call_openrouter(prompt, model=model, system=system)
            elif provider == "nvidia-nim":
                resp = _call_nvidia_nim(prompt, model=model, system=system)
            else:
                raise RuntimeError(f"Unknown provider: {provider}")

            if resp:
                return resp, model
        except Exception as e:
            print(f"  ↻ {model} failed: {e}", file=sys.stderr)
            continue

    raise RuntimeError(f"All {provider} models exhausted")


# ── Triage Logic ──────────────────────────────────────────────────────────────

def _build_prompt(candidate_path: str, findings: dict = None, context: dict = None) -> str:
    """Build the triage prompt from candidate file + scanner findings."""
    lines = []

    # Candidate code
    try:
        code = Path(candidate_path).read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return f"Error reading candidate file: {e}"

    lines.append(f"## Candidate File: {candidate_path}")
    lines.append(f"```")
    lines.append(code[:8000])  # Cap at 8K chars to avoid context overflow
    lines.append(f"```")
    lines.append("")

    # Scanner findings
    if findings:
        lines.append("## Automated Scanner Findings")
        for scanner_name, result in findings.items():
            lines.append(f"\n### {scanner_name}")
            if isinstance(result, dict):
                lines.append(f"```json")
                lines.append(json.dumps(result, indent=2, default=str)[:2000])
                lines.append(f"```")
            else:
                lines.append(str(result)[:2000])
        lines.append("")

    # Additional context
    if context:
        lines.append("## Additional Context")
        for k, v in context.items():
            lines.append(f"- {k}: {v}")
        lines.append("")

    lines.append("## Your Task")
    lines.append("Analyze the candidate file and scanner findings above.")
    lines.append("Produce a structured triage report as a JSON object.")
    lines.append("Be specific: cite exact code lines, scanner matches, and MITRE techniques.")

    return "\n".join(lines)


def _parse_json_response(raw: str) -> dict:
    """Extract JSON from LLM response (handles markdown wrapping)."""
    # Try direct parse
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Try extracting from markdown code block
    if "```json" in raw:
        raw = raw.split("```json")[1].split("```")[0].strip()
    elif "```" in raw:
        raw = raw.split("```")[1].split("```")[0].strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Return as raw text wrapped in structure
        return {
            "verdict": "INCONCLUSIVE",
            "confidence": 0.0,
            "severity": "none",
            "summary": raw[:500],
            "findings": [],
            "false_positive_likelihood": 0.5,
            "recommended_actions": ["manual_review"],
            "scanner_correlation": "LLM response could not be parsed as JSON",
            "_raw": raw,
        }


def triage(
    candidate_path: str,
    findings: dict = None,
    context: dict = None,
    provider: str = None,
    json_output: bool = False,
) -> dict:
    """
    Run MR. Robot triage on a candidate file.

    Args:
        candidate_path: Path to the file to triage
        findings: Dict of {scanner_name: result} from automated scanners
        context: Optional additional context (scenario name, source, etc.)
        provider: LLM provider (default: ollama-cloud)
        json_output: If True, return raw dict; if False, return formatted string

    Returns:
        Triage report dict (or formatted string if json_output=False)
    """
    provider = provider or DEFAULT_PROVIDER
    start_time = time.perf_counter()

    prompt = _build_prompt(candidate_path, findings, context)

    try:
        raw_response, model_used = _call_llm(provider, prompt, system=SYSTEM_PROMPT)
    except RuntimeError as e:
        error_report = {
            "verdict": "ERROR",
            "confidence": 0.0,
            "severity": "none",
            "summary": f"Triage failed: {e}",
            "findings": [],
            "false_positive_likelihood": 1.0,
            "recommended_actions": ["retry", "manual_review"],
            "scanner_correlation": "N/A — LLM unavailable",
        }
        if json_output:
            return error_report
        return json.dumps(error_report, indent=2)

    elapsed = time.perf_counter() - start_time
    report = _parse_json_response(raw_response)

    # Enrich with metadata
    report["_meta"] = {
        "agent": "MR. Robot",
        "version": "1.0.0",
        "provider": provider,
        "model": model_used,
        "candidate": str(candidate_path),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": round(elapsed, 2),
        "scanners_used": list(findings.keys()) if findings else [],
    }

    if json_output:
        return report

    # Human-readable format
    lines = [
        "=" * 60,
        f"  MR. ROBOT — TRIAGE REPORT",
        "=" * 60,
        f"  Candidate:  {candidate_path}",
        f"  Verdict:    {report.get('verdict', 'N/A')} (confidence: {report.get('confidence', 'N/A')})",
        f"  Severity:   {report.get('severity', 'N/A')}",
        f"  FP Likely:  {report.get('false_positive_likelihood', 'N/A')}",
        f"  Model:      {model_used} ({provider})",
        f"  Duration:   {round(elapsed, 1)}s",
        "-" * 60,
        "",
        report.get("summary", "No summary available"),
        "",
    ]

    if report.get("findings"):
        lines.append("FINDINGS:")
        for i, f in enumerate(report["findings"], 1):
            lines.append(f"  {i}. [{f.get('type', 'unknown')}] {f.get('description', '')}")
            if f.get("evidence"):
                lines.append(f"     Evidence: {f['evidence'][:200]}")
            if f.get("mitre_id"):
                lines.append(f"     MITRE: {f['mitre_id']}")
        lines.append("")

    if report.get("recommended_actions"):
        lines.append("RECOMMENDED ACTIONS:")
        for a in report["recommended_actions"]:
            lines.append(f"  → {a}")
        lines.append("")

    if report.get("scanner_correlation"):
        lines.append(f"SCANNER CORRELATION: {report['scanner_correlation']}")
        lines.append("")

    return "\n".join(lines)


# ── Health Check ──────────────────────────────────────────────────────────────

def health(provider: str = None) -> tuple[bool, str]:
    """Check if the triage agent can reach its LLM provider."""
    provider = provider or DEFAULT_PROVIDER
    key = _get_api_key(provider)
    if not key:
        return False, f"No API key for {provider} (env: {PROVIDERS[provider]['env_key']})"

    # Try a minimal prompt
    try:
        resp, model = _call_llm(provider, "Reply with exactly: OK", system="You are a test.")
        if resp and "OK" in resp.upper():
            return True, f"{provider}/{model} OK"
        return True, f"{provider}/{model} responded (unexpected: {resp[:50]})"
    except RuntimeError as e:
        return False, str(e)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="MR. Robot — Autonomous Triage Agent")
    ap.add_argument("candidate", nargs="?", help="Path to candidate file to triage")
    ap.add_argument("--findings", help="Path to scanner findings JSON file")
    ap.add_argument("--context", help="Path to additional context JSON file")
    ap.add_argument("--provider", default=DEFAULT_PROVIDER, choices=list(PROVIDERS),
                    help=f"LLM provider (default: {DEFAULT_PROVIDER})")
    ap.add_argument("--json", action="store_true", help="Output raw JSON (machine-readable)")
    ap.add_argument("--health", action="store_true", help="Check provider health and exit")
    args = ap.parse_args()

    if args.health:
        ok, msg = health(args.provider)
        print(("✅ " if ok else "🔴 ") + msg)
        sys.exit(0 if ok else 1)

    if not args.candidate:
        ap.error("candidate file required (or pass --health)")

    findings = None
    if args.findings:
        with open(args.findings) as f:
            findings = json.load(f)

    context = None
    if args.context:
        with open(args.context) as f:
            context = json.load(f)

    result = triage(
        args.candidate,
        findings=findings,
        context=context,
        provider=args.provider,
        json_output=args.json,
    )

    if isinstance(result, dict):
        print(json.dumps(result, indent=2, default=str))
    else:
        print(result)
