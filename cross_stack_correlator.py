#!/usr/bin/env python3
"""
Cross-Stack Correlator — Find Evil Hackathon

Query: look back over audit trail for MALICIOUS rows sharing
the same tool_name prefix as the current scanner. Three or more hits
indicates a correlated attack wave and triggers severity escalation
to CRITICAL.

Integrates with all scanners (skill, ioc, yara, sigma, secrets, nhi, infostealer)
for comprehensive campaign detection.
"""

from __future__ import annotations

import json
import logging
import sqlite3
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
    correlated_scanners: list[str] = None

    def __post_init__(self):
        if self.correlated_scanners is None:
            object.__setattr__(self, "correlated_scanners", [])


class CampaignDetector:
    """
    Lightweight audit-trail campaign detector with multi-scanner correlation.

    The SES (Scanner Event Source) categorization maps tool names to
    the scanner family that produced them:

        skill_scanner   -> skill
        ioc_scanner     -> ioc
        scan_yara       -> yara
        secrets_detector -> secrets
        sigma_scanner   -> sigma
        nhi_governance  -> nhi
        infostealer_intel -> infostealer

    Callers should pass the originating tool_name so the correlator
    can group by the same family.
    """

    SES_TOOL_PREFIXES: dict[str, str] = {
        "skill_scanner": "skill",
        "ioc_scanner": "ioc",
        "scan_yara": "yara",
        "secrets_detector": "secrets",
        "sigma_scanner": "sigma",
        "nhi_governance": "nhi",
        "infostealer_intel": "infostealer",
    }

    # Cross-scanner correlation groups (e.g., all exfil-related scanners)
    CORRELATION_GROUPS: dict[str, list[str]] = {
        "exfiltration": ["ioc", "yara", "secrets", "sigma", "nhi", "infostealer"],
        "supply_chain": ["skill", "ioc", "yara", "sigma"],
        "credential_theft": ["secrets", "nhi", "infostealer", "ioc"],
        "persistence": ["skill", "yara", "sigma", "nhi"],
        "ai_manipulation": ["skill", "yara", "sigma"],
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

    def _get_correlation_group(self, prefix: str) -> list[str]:
        """Get all scanner prefixes in the same correlation group."""
        for group_name, group_prefixes in self.CORRELATION_GROUPS.items():
            if prefix in group_prefixes:
                return group_prefixes
        return [prefix]

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
        family (and correlation group) in the last ``window_hours`` hours
        when the verdict is MALICIOUS.

        Returns ``campaign_detected=True`` when count >= ``threshold``.
        """
        db = db_path or self.db_path
        if current_verdict not in ("MALICIOUS",):
            return CampaignResult(
                campaign_detected=False,
                detail="current_verdict is not MALICIOUS",
            )

        prefix = self._prefix_for(tool_name)
        correlation_prefixes = self._get_correlation_group(prefix)

        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
            cutoff_ts = cutoff.timestamp()
            with sqlite3.connect(db) as conn:
                # Build LIKE conditions for each prefix in correlation group
                like_conditions = " OR ".join(["tool_name LIKE ?"] * len(correlation_prefixes))
                params = [cutoff_ts] + [f"%{p}%" for p in correlation_prefixes]

                row = conn.execute(
                    f"""
                    SELECT COUNT(*) AS cnt, GROUP_CONCAT(DISTINCT tool_name) as tools
                    FROM executions
                    WHERE verdict = 'MALICIOUS'
                      AND timestamp >= ?
                      AND ({like_conditions})
                    """,
                    params,
                ).fetchone()
                count = int(row[0]) if row else 0
                correlated_tools = row[1].split(",") if row and row[1] else []
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
                f", prefix={prefix}, correlation_group={correlation_prefixes}"
                f", tools={correlated_tools}"
            ),
            correlated_scanners=correlated_tools,
        )

    def get_recent_campaigns(self, window_hours: int = 24, db_path: Optional[str] = None) -> list[dict]:
        """Get all recent campaign-like patterns from the audit trail."""
        db = db_path or self.db_path
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
            cutoff_ts = cutoff.timestamp()
            with sqlite3.connect(db) as conn:
                rows = conn.execute(
                    """
                    SELECT tool_name, COUNT(*) as cnt, MAX(timestamp) as last_seen
                    FROM executions
                    WHERE verdict = 'MALICIOUS'
                      AND timestamp >= ?
                    GROUP BY tool_name
                    HAVING cnt >= 2
                    ORDER BY cnt DESC
                    """,
                    (cutoff_ts,),
                ).fetchall()
                return [
                    {
                        "tool_name": r[0],
                        "count": r[1],
                        "last_seen": datetime.fromtimestamp(r[2], tz=timezone.utc).isoformat(),
                        "prefix": self._prefix_for(r[0]),
                    }
                    for r in rows
                ]
        except Exception as exc:
            logger.warning("recent campaigns query failed: %s", exc)
            return []


def init_audit_db(db_path: Optional[str] = None) -> None:
    """Initialize the audit trail database schema."""
    path = db_path or str(Path(__file__).resolve().parent / "logs" / "audit_trail.db")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool_name TEXT NOT NULL,
                verdict TEXT NOT NULL,
                timestamp REAL NOT NULL,
                file_path TEXT,
                metadata JSON
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_executions_verdict_time ON executions(verdict, timestamp)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_executions_tool_name ON executions(tool_name)"
        )
        conn.commit()


def log_execution(
    tool_name: str,
    verdict: str,
    file_path: str = "",
    metadata: dict | None = None,
    db_path: Optional[str] = None,
    timestamp: float | None = None,
) -> None:
    """Log a scanner execution to the audit trail."""
    path = db_path or str(Path(__file__).resolve().parent / "logs" / "audit_trail.db")
    ts = timestamp or datetime.now(timezone.utc).timestamp()
    with sqlite3.connect(path) as conn:
        conn.execute(
            "INSERT INTO executions (tool_name, verdict, timestamp, file_path, metadata) VALUES (?, ?, ?, ?, ?)",
            (tool_name, verdict, ts, file_path, json.dumps(metadata or {})),
        )
        conn.commit()