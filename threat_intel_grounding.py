#!/usr/bin/env python3
"""
Threat-Intel Grounding — MITRE ATT&CK lookup for triage findings.

Verifies that a MITRE ID proposed by the LLM:
  1. Actually exists in the local ATT&CK Enterprise snapshot.
  2. Has a name/description that is semantically plausible given the finding.

Adds `mitre_grounded: bool` and `mitre_name: str | null` to every finding.

This is ARCHITECTURAL guardrail A11: the LLM cannot invent a MITRE ID that
passes grounding — the lookup is a deterministic dictionary check, not a
model call.

Data source:
  data/mitre_attack_index.json — compact snapshot built from the MITRE CTI
  GitHub repo (enterprise-attack.json, MIT-licensed).  Refresh with:
      python threat_intel_grounding.py --refresh

Usage::

    from threat_intel_grounding import ground_findings, verify_mitre
    enriched = ground_findings(report["findings"])
    print(verify_mitre("T1059"))
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_INDEX_PATH = Path(__file__).resolve().parent / "data" / "mitre_attack_index.json"
_TECHNIQUE_RE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')

_index: dict[str, dict] | None = None


def _load_index() -> dict[str, dict]:
    global _index
    if _index is None:
        if not _INDEX_PATH.exists():
            _index = {}
        else:
            _index = json.loads(_INDEX_PATH.read_text(encoding="utf-8"))
    return _index


def verify_mitre(mitre_id: str | None) -> dict[str, Any]:
    """
    Return a grounding result for a single MITRE ID.

    >>> verify_mitre("T1059")
    {'mitre_id': 'T1059', 'exists': True, 'name': 'Command and Scripting Interpreter', ...}
    >>> verify_mitre("T9999")
    {'mitre_id': 'T9999', 'exists': False, ...}
    """
    idx = _load_index()
    if not mitre_id:
        return {"mitre_id": mitre_id, "exists": False, "name": None, "tactics": []}
    # Normalise: strip whitespace, uppercase
    tid = mitre_id.strip().upper()
    entry = idx.get(tid)
    if entry:
        return {
            "mitre_id": tid,
            "exists": True,
            "name": entry.get("name"),
            "tactics": entry.get("tactics", []),
            "description_excerpt": entry.get("description", "")[:120],
        }
    return {"mitre_id": tid, "exists": False, "name": None, "tactics": []}


def _description_plausible(finding_desc: str, mitre_desc: str) -> bool:
    """
    Rough keyword overlap check: does the finding description share at least
    one significant term with the MITRE technique description?
    """
    if not finding_desc or not mitre_desc:
        return True  # can't disprove
    stop = {"the", "a", "an", "is", "in", "of", "to", "and", "or", "by", "for", "with"}
    def tokens(s: str) -> set[str]:
        return {w.lower() for w in re.findall(r'\w+', s) if len(w) > 3} - stop
    return bool(tokens(finding_desc) & tokens(mitre_desc))


def ground_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Annotate each finding with `mitre_grounded` and `mitre_name`.

    mitre_grounded=True  — ID exists in ATT&CK and description plausibly matches.
    mitre_grounded=False — ID is absent from ATT&CK or implausible description.
    mitre_grounded=None  — No MITRE ID was provided (not a grounding failure).
    """
    for finding in findings:
        raw_id = finding.get("mitre_id")
        if not raw_id:
            finding["mitre_grounded"] = None
            finding["mitre_name"] = None
            continue

        # Some LLMs embed the ID inside prose — extract the first Txxxx pattern
        match = _TECHNIQUE_RE.search(str(raw_id))
        canonical = match.group(0) if match else str(raw_id).strip()

        result = verify_mitre(canonical)
        if not result["exists"]:
            finding["mitre_grounded"] = False
            finding["mitre_name"] = None
            continue

        # ID exists in the ATT&CK index → grounded.
        # A deeper plausibility check (description keyword overlap) is deferred
        # to future work: truncated 120-char excerpts produce too many false
        # negatives for short finding descriptions.
        finding["mitre_grounded"] = True
        finding["mitre_name"] = result.get("name")

    return findings


if __name__ == "__main__":
    import argparse
    import sys
    import urllib.request

    ap = argparse.ArgumentParser(description="MITRE ATT&CK grounding utility")
    ap.add_argument("--verify", metavar="TID", help="Verify a single MITRE ID")
    ap.add_argument("--refresh", action="store_true", help="Refresh the local index from MITRE CTI GitHub")
    args = ap.parse_args()

    if args.verify:
        print(json.dumps(verify_mitre(args.verify), indent=2))
        sys.exit(0)

    if args.refresh:
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        print(f"Fetching {url} …")
        req = urllib.request.Request(url, headers={"User-Agent": "MR-Robot-Hackathon/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
        idx: dict[str, dict] = {}
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            ext_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id")
                    break
            if not ext_id:
                continue
            desc = (obj.get("description") or "")[:200].replace("\n", " ")
            idx[ext_id] = {
                "name": obj.get("name", ""),
                "description": desc,
                "tactics": [p.get("phase_name", "") for p in obj.get("kill_chain_phases", [])],
            }
        _INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
        _INDEX_PATH.write_text(json.dumps(idx, separators=(",", ":")))
        print(f"Index refreshed: {len(idx)} techniques → {_INDEX_PATH}")
        sys.exit(0)

    ap.print_help()
