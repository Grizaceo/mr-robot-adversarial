"""Tests for cross-stack correlator — campaign_detected signal."""
from __future__ import annotations
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest

from cross_stack_correlator import CampaignDetector


@pytest.fixture
def detector(tmp_path: Path) -> CampaignDetector:
    db = tmp_path / "audit_trail.db"
    with sqlite3.connect(db) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool_name TEXT,
                verdict TEXT,
                timestamp REAL
            )
            """
        )
        conn.commit()
    return CampaignDetector(str(db))


def _seed(conn: sqlite3.Connection, rows: list[tuple[str, str, float]]) -> None:
    conn.executemany(
        "INSERT INTO executions (tool_name, verdict, timestamp) VALUES (?, ?, ?)",
        rows,
    )
    conn.commit()


def test_no_campaign_when_below_threshold(detector: CampaignDetector) -> None:
    now = datetime.now(timezone.utc)
    rows: list[tuple[str, str, float]] = []
    for i in range(2):
        rows.append(
            (
                f"skill_scanner_{i}",
                "MALICIOUS",
                (now - timedelta(hours=1)).timestamp(),
            )
        )
    with sqlite3.connect(detector.db_path) as conn:
        _seed(conn, rows)
    result = detector.correlate("skill_scanner_0", "MALICIOUS")
    assert result.campaign_detected is False
    assert result.file_count == 2


def test_campaign_detected_at_threshold(detector: CampaignDetector) -> None:
    now = datetime.now(timezone.utc)
    rows: list[tuple[str, str, float]] = []
    for i in range(3):
        rows.append(
            (
                "skill_scanner",
                "MALICIOUS",
                (now - timedelta(hours=1)).timestamp(),
            )
        )
    with sqlite3.connect(detector.db_path) as conn:
        _seed(conn, rows)
    result = detector.correlate("skill_scanner", "MALICIOUS")
    assert result.campaign_detected is True
    assert result.file_count == 3
    assert result.severity_escalation == "CRITICAL"


def test_out_of_window_events_excluded(detector: CampaignDetector) -> None:
    now = datetime.now(timezone.utc)
    rows = [
        (
            "skill_scanner",
            "MALICIOUS",
            (now - timedelta(hours=1)).timestamp(),
        ),
        (
            "skill_scanner",
            "MALICIOUS",
            (now - timedelta(hours=1)).timestamp(),
        ),
        (
            "skill_scanner",
            "MALICIOUS",
            (now - timedelta(hours=30)).timestamp(),
        ),
    ]
    with sqlite3.connect(detector.db_path) as conn:
        _seed(conn, rows)
    result = detector.correlate("skill_scanner", "MALICIOUS", window_hours=24)
    assert result.campaign_detected is False
    assert result.file_count == 2


def test_benign_rows_do_not_count(detector: CampaignDetector) -> None:
    now = datetime.now(timezone.utc)
    rows = [
        ("skill_scanner", "BENIGN", (now - timedelta(hours=1)).timestamp()),
        ("skill_scanner", "BENIGN", (now - timedelta(hours=1)).timestamp()),
        ("skill_scanner", "BENIGN", (now - timedelta(hours=1)).timestamp()),
    ]
    with sqlite3.connect(detector.db_path) as conn:
        _seed(conn, rows)
    result = detector.correlate("skill_scanner", "MALICIOUS")
    assert result.campaign_detected is False
    assert result.file_count == 0


def test_severity_escalation_applied(detector: CampaignDetector) -> None:
    now = datetime.now(timezone.utc)
    rows = [
        ("ioc_scanner", "MALICIOUS", (now - timedelta(hours=1)).timestamp()),
        ("ioc_scanner", "MALICIOUS", (now - timedelta(hours=1)).timestamp()),
        ("ioc_scanner", "MALICIOUS", (now - timedelta(hours=1)).timestamp()),
    ]
    with sqlite3.connect(detector.db_path) as conn:
        _seed(conn, rows)
    result = detector.correlate("ioc_scanner", "MALICIOUS")
    assert result.campaign_detected is True
    assert result.severity_escalation == "CRITICAL"


def test_json_output_always_contains_keys(detector: CampaignDetector) -> None:
    now = datetime.now(timezone.utc)
    with sqlite3.connect(detector.db_path) as conn:
        _seed(
            conn,
            [
                (
                    "scan_yara",
                    "MALICIOUS",
                    (now - timedelta(hours=1)).timestamp(),
                )
            ],
        )
    result = detector.correlate("scan_yara", "MALICIOUS")
    payload = {
        "campaign_detected": result.campaign_detected,
        "ioc_pattern": None,
    }
    assert "campaign_detected" in payload
    assert "ioc_pattern" in payload
    assert result.campaign_detected is False
    assert result.file_count == 1
