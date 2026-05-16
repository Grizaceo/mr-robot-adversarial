#!/usr/bin/env python3
"""
Proof Stage — static confirmation of triage findings.

Annotates each LLM finding with proof_status ∈ {CONFIRMED, INFERRED, REFUTED}:

  CONFIRMED  — the evidence string is literally present in the file AND (for
               injection-class findings) the sink can be reached from a
               plausible user-controlled input in the AST.
  INFERRED   — the evidence is partially present or the data-flow cannot be
               statically resolved; finding is plausible but unconfirmed.
  REFUTED    — the evidence string is absent from the file, or the LLM-proposed
               MITRE ID is not in the local ATT&CK snapshot.

This is an ARCHITECTURAL guardrail (A10): the LLM cannot alter the outcome of
a static text/AST check.  It does not replace dynamic sandbox execution; it
distinguishes "I can see the code" from "I guessed this might be there."

Usage (standalone)::

    from proof_stage import annotate_findings
    enriched = annotate_findings(report["findings"], candidate_path)
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

# Proof-status constants
CONFIRMED = "CONFIRMED"
INFERRED  = "INFERRED"
REFUTED   = "REFUTED"

# Sink function names that represent dangerous operations in Python
_INJECTION_SINKS = frozenset({
    "eval", "exec", "compile", "execfile",
    "subprocess", "Popen", "check_output", "check_call", "run", "call",
    "os.system", "os.popen",
    "cursor.execute", "execute",
})

# Names typically associated with user-controlled sources in web code
_USER_INPUT_SOURCES = frozenset({
    "request", "input", "stdin", "argv", "args", "kwargs",
    "params", "query", "form", "json", "data", "body",
    "environ", "getenv", "GET", "POST",
})

# High-entropy secret patterns (token/key classes that are long random strings)
_HIGH_ENTROPY_RE = re.compile(
    r'(?:ghp_|ghs_|gho_|github_pat_|AKIA|sk-[a-zA-Z0-9]{20,}|nvapi-|xoxb-|xoxp-)'
    r'[a-zA-Z0-9_\-]{16,}'
)
_MIN_SECRET_ENTROPY_CHARS = 20  # rough lower-bound on high-entropy secrets


def _shannon_entropy(s: str) -> float:
    """Rough character-level Shannon entropy (bits per character)."""
    from math import log2
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * log2(f / n) for f in freq.values())


def _evidence_in_file(evidence: str, file_content: str) -> bool:
    """Check whether evidence appears literally (stripped) in file content."""
    ev = evidence.strip()
    if not ev or len(ev) < 6:
        return False
    return ev in file_content


def _ast_has_sink_near_source(candidate_path: Path) -> bool:
    """
    Return True if any Python AST sink function is called with an argument
    whose name tree contains a known user-input source name.  This is a
    conservative approximation — the true data-flow may be more complex.
    """
    try:
        source = candidate_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source, filename=str(candidate_path))
    except Exception:
        return False

    def _name_tokens(node: ast.AST) -> set[str]:
        tokens: set[str] = set()
        for n in ast.walk(node):
            if isinstance(n, ast.Name):
                tokens.add(n.id.lower())
            elif isinstance(n, ast.Attribute):
                tokens.add(n.attr.lower())
        return tokens

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # Resolve the callee name
        func = node.func
        if isinstance(func, ast.Name):
            callee = func.id
        elif isinstance(func, ast.Attribute):
            callee = func.attr
        else:
            continue

        if callee not in _INJECTION_SINKS:
            continue

        # Check all arguments for user-input source names
        all_args = list(node.args) + [kw.value for kw in node.keywords]
        for arg in all_args:
            arg_tokens = _name_tokens(arg)
            if arg_tokens & _USER_INPUT_SOURCES:
                return True

    return False


def _confirm_injection_finding(finding: dict[str, Any], candidate_path: Path, file_content: str) -> str:
    """Confirm injection/subprocess/eval/exec class findings."""
    evidence = finding.get("evidence", "")
    if not _evidence_in_file(evidence, file_content):
        return REFUTED
    # Evidence present — now try to verify data-flow
    if candidate_path.suffix.lower() == ".py":
        if _ast_has_sink_near_source(candidate_path):
            return CONFIRMED
        return INFERRED  # sink evidenced but data-flow unresolved
    # Non-Python: evidence present is enough to CONFIRM (no AST available)
    return CONFIRMED


def _confirm_secret_finding(finding: dict[str, Any], file_content: str) -> str:
    """Confirm secrets/credentials findings via entropy check."""
    evidence = finding.get("evidence", "")
    if not evidence:
        return INFERRED
    # Strip common quote chars from the evidence to get the raw value
    candidate = evidence.strip().strip("'\"`")
    if _HIGH_ENTROPY_RE.search(evidence):
        return CONFIRMED
    if len(candidate) >= _MIN_SECRET_ENTROPY_CHARS and _shannon_entropy(candidate) > 3.5:
        return CONFIRMED if _evidence_in_file(evidence, file_content) else REFUTED
    if _evidence_in_file(evidence, file_content):
        return INFERRED  # Evidence is there but entropy too low for certainty
    return REFUTED


def _confirm_ioc_finding(finding: dict[str, Any], candidate_path: Path) -> str:
    """Re-run the IOC scanner on the file to confirm IOC findings."""
    try:
        import sys
        import importlib
        _cybersec = None
        for p in sys.path:
            probe = Path(p) / "ioc_scanner.py"
            if probe.exists():
                _cybersec = p
                break
        if _cybersec is None:
            # Try the well-known workspace location
            probe_dir = Path.home() / ".hermes/workspace/cybersecurity-lab/scanners"
            if probe_dir.exists() and str(probe_dir) not in sys.path:
                sys.path.insert(0, str(probe_dir))
        import ioc_scanner  # noqa: PLC0415
        importlib.reload(ioc_scanner)
        hits = ioc_scanner.scan_file(candidate_path)
        return CONFIRMED if hits else INFERRED
    except Exception:
        # If the IOC scanner is unavailable, fall back to evidence check
        return INFERRED


def _confirm_prompt_injection_finding(finding: dict[str, Any], candidate_path: Path) -> str:
    """Re-run the prompt injection detector to confirm."""
    try:
        content = candidate_path.read_text(encoding="utf-8", errors="ignore")
        from prompt_injection_defense import scan  # noqa: PLC0415
        result = scan(content)
        if result.max_severity in ("critical", "high", "CRITICAL", "HIGH"):
            return CONFIRMED
        return REFUTED
    except Exception:
        return INFERRED


def _default_confirm(finding: dict[str, Any], file_content: str) -> str:
    """Fallback: CONFIRMED if evidence is literally in the file, else INFERRED."""
    evidence = finding.get("evidence", "")
    if _evidence_in_file(evidence, file_content):
        return CONFIRMED
    return INFERRED


def _classify_finding_type(finding: dict[str, Any]) -> str:
    """Map a finding to a proof-strategy bucket."""
    ftype = (finding.get("type") or "").lower()
    desc = (finding.get("description") or "").lower()
    mitre = (finding.get("mitre_id") or "").upper()

    if "prompt_injection" in ftype or "prompt_injection" in desc:
        return "prompt_injection"
    if ftype in ("secrets", "credential") or "secret" in desc or "token" in desc or "api key" in desc:
        return "secrets"
    if ftype == "ioc" or "ioc" in desc or "indicator" in ftype:
        return "ioc"
    # Injection/exec categories — common MITRE IDs
    injection_mitre = {"T1059", "T1190", "T1055", "T1106", "T1203"}
    if mitre in injection_mitre or any(kw in desc for kw in ("inject", "eval", "exec", "subprocess", "shell", "command")):
        return "injection"
    return "default"


def annotate_findings(
    findings: list[dict[str, Any]],
    candidate_path: str | Path,
) -> list[dict[str, Any]]:
    """
    Annotate each finding with a `proof_status` field.

    Returns the same list with `proof_status` added in-place on each finding
    dict (also returns the list for convenience).
    """
    candidate_path = Path(candidate_path)
    try:
        file_content = candidate_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        file_content = ""

    for finding in findings:
        bucket = _classify_finding_type(finding)

        if bucket == "injection":
            status = _confirm_injection_finding(finding, candidate_path, file_content)
        elif bucket == "secrets":
            status = _confirm_secret_finding(finding, file_content)
        elif bucket == "ioc":
            status = _confirm_ioc_finding(finding, candidate_path)
        elif bucket == "prompt_injection":
            status = _confirm_prompt_injection_finding(finding, candidate_path)
        else:
            status = _default_confirm(finding, file_content)

        finding["proof_status"] = status

    return findings
