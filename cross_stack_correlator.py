#!/usr/bin/env python3
"""
Cross-Stack Correlator — campaign signal from execution audit trail.

Query: look back 24h in the executions table for MALICIOUS rows sharing
the same tool_name prefix as the current scanner.  Three or more hits
indicates a correlated attack wave and triggers severity escalation
to CRITICAL.

No external telemetry is required; this uses the existing audit_trail.db
created by execution_logger.  A lightweight SQLite query keeps latency
well under 50ms on the current corpus size (hundreds to low-thousands
of rows).

Design rationale: rather than wiring live SIEM/EDR/IdP connectors (out of
scope for a one-file-at-a-time open-source pipeline), the correlator derives
a campaign signal purely from the local audit trail.  This keeps the feature
self-contained and reproducible while still surfacing correlated attack waves.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("cross-stack-correlator")


@dataclass(frozen=True)
class CampaignResult:
    campaign_detected: bool
    file_count: int = 0
    severity_escalation: Optional[str] = None
    tool_name_prefix: str = ""
    window_hours: int = 24
    detail: str = ""


class CampaignDetector:
    """
    Lightweight audit-trail campaign detector.

    The SES (Scanner Event Source) categorization maps tool names to
    the scanner family that produced them:

        skill_scanner  -> skill
        ioc_scanner    -> ioc
        scan_yara      -> yara
        secrets_detector -> secrets

    Callers should pass the originating tool_name so the correlator
    can group by the same family.
    """

    SES_TOOL_PREFIXES: dict[str, str] = {
        "skill_scanner": "skill",
        "ioc_scanner": "ioc",
        "scan_yara": "yara",
        "secrets_detector": "secrets",
    }

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = str(
            Path(db_path).resolve()
            if db_path
            else Path(__file__).resolve().parent / "logs" / "audit_trail.db"
        )

    def _prefix_for(self, tool_name: str) -> str:
        lower = tool_name.lower()
        for key, prefix in self.SES_TOOL_PREFIXES.items():
            if key in lower:
                return prefix
        # Fallback: return lowercased tool_name stripped of digits/underscores.
        return "".join(ch for ch in lower if ch.isalpha())

    def correlate(
        self,
        tool_name: str,
        current_verdict: str,
        window_hours: int = 24,
        threshold: int = 3,
        db_path: Optional[str] = None,
    ) -> CampaignResult:
        """
        Return a CampaignResult for executions sharing the same scanner
        family in the last ``window_hours`` hours when the verdict is
        MALICIOUS.

        Returns ``campaign_detected=True`` when count >= ``threshold``.
        """
        db = db_path or self.db_path
        if current_verdict not in ("MALICIOUS",):
            return CampaignResult(
                campaign_detected=False,
                detail="current_verdict is not MALICIOUS",
            )

        prefix = self._prefix_for(tool_name)
        try:
            import sqlite3

            cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
            cutoff_ts = cutoff.timestamp()
            with sqlite3.connect(db) as conn:
                row = conn.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM executions
                    WHERE verdict = 'MALICIOUS'
                      AND timestamp >= ?
                      AND tool_name LIKE ?
                    """,
                    (cutoff_ts, f"%{prefix}%"),
                ).fetchone()
                count = int(row[0]) if row else 0
        except Exception as exc:
            logger.warning("campaign query failed: %s", exc)
            return CampaignResult(
                campaign_detected=False,
                detail=f"query_failed: {exc}",
            )

        detected = count >= threshold
        return CampaignResult(
            campaign_detected=detected,
            file_count=count,
            severity_escalation="CRITICAL" if detected else None,
            tool_name_prefix=prefix,
            window_hours=window_hours,
            detail=(
                f"detected={detected}, count={count}, threshold={threshold}"
                f", prefix={prefix}"
            ),
        )
