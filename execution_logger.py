#!/usr/bin/env python3
"""
Execution Logger — MR. Robot Adversarial (Requirement #8: Agent Execution Logs)

Adapted from KISS Discovery Engine's FastTracker (SQLite WAL mode).
Logs every MCP tool invocation with full input/output for audit trail.

Schema:
    executions: id, run_id, tool_name, input_json, output_json,
                duration_ms, timestamp, agent_id, verdict

SANS Requirement #8: "Agent execution logs — Can a judge trace each finding
to a specific execution?" This logger makes that possible.

Usage:
    from execution_logger import ExecutionLogger
    logger = ExecutionLogger("logs/audit.db")
    logger.log("scan_file", {"filepath": "/tmp/x.py"}, {"verdict": "MALICIOUS"}, 1500.0)
    entries = logger.query(limit=50)
    logger.close()
"""

import sqlite3
import json
import time
import os
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("execution-logger")


class ExecutionLogger:
    """
    SQLite-based execution audit trail.
    WAL mode for concurrent writes without lock contention.
    """

    def __init__(self, db_path: str = "logs/audit_trail.db"):
        self.db_path = str(Path(db_path).resolve())
        self._is_memory = self.db_path == ":memory:"
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()
        logger.info(f"ExecutionLogger initialized: {self.db_path}")

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self):
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT,
                    tool_name TEXT NOT NULL,
                    input_json TEXT,
                    output_json TEXT,
                    duration_ms REAL,
                    verdict TEXT,
                    severity TEXT,
                    confidence REAL,
                    agent_id TEXT DEFAULT 'mr_robot',
                    timestamp REAL,
                    created_at TEXT DEFAULT (datetime('now'))
                )
            """)
            # Index for fast queries by tool and time
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_exec_tool ON executions(tool_name)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_exec_time ON executions(timestamp)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_exec_verdict ON executions(verdict)
            """)
            conn.commit()

    def log(
        self,
        tool_name: str,
        input_data: dict,
        output_data: dict,
        duration_ms: float,
        run_id: str = None,
        agent_id: str = "mr_robot",
    ) -> int:
        """
        Log a tool execution.

        Args:
            tool_name: Name of the MCP tool called
            input_data: Input arguments dict
            output_data: Output result dict
            duration_ms: Execution time in milliseconds
            run_id: Optional run identifier for grouping
            agent_id: Which agent made the call

        Returns:
            Row ID of the inserted record
        """
        if not run_id:
            run_id = f"run_{int(time.time() * 1000)}"

        # Extract key fields from output for indexing
        verdict = None
        severity = None
        confidence = None
        if isinstance(output_data, dict):
            verdict = output_data.get("verdict") or output_data.get("overall_verdict")
            severity = output_data.get("severity")
            confidence = output_data.get("confidence")

        try:
            with self.connect() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO executions
                    (run_id, tool_name, input_json, output_json, duration_ms,
                     verdict, severity, confidence, agent_id, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        tool_name,
                        json.dumps(input_data, default=str),
                        json.dumps(output_data, default=str)[:50000],  # Cap at 50KB
                        duration_ms,
                        verdict,
                        severity,
                        confidence,
                        agent_id,
                        time.time(),
                    ),
                )
                conn.commit()
                return cursor.lastrowid
        except Exception as e:
            logger.error(f"Failed to log execution: {e}")
            return -1

    def query(
        self,
        tool_name: str = None,
        verdict: str = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        """
        Query execution log entries.

        Args:
            tool_name: Filter by tool name
            verdict: Filter by verdict
            limit: Max results
            offset: Pagination offset

        Returns:
            List of execution records as dicts
        """
        conditions = []
        params = []

        if tool_name:
            conditions.append("tool_name = ?")
            params.append(tool_name)
        if verdict:
            conditions.append("verdict = ?")
            params.append(verdict)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        params.extend([limit, offset])

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"""
                SELECT * FROM executions
                {where}
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                """,
                params,
            ).fetchall()

        return [dict(row) for row in rows]

    def get_run(self, run_id: str) -> list[dict]:
        """Get all executions for a specific run."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM executions WHERE run_id = ? ORDER BY timestamp",
                (run_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def summary(self) -> dict:
        """Get summary statistics of all executions."""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM executions").fetchone()[0]
            by_tool = conn.execute(
                "SELECT tool_name, COUNT(*) FROM executions GROUP BY tool_name"
            ).fetchall()
            by_verdict = conn.execute(
                "SELECT verdict, COUNT(*) FROM executions WHERE verdict IS NOT NULL GROUP BY verdict"
            ).fetchall()
            avg_duration = conn.execute(
                "SELECT AVG(duration_ms) FROM executions"
            ).fetchone()[0]

        return {
            "total_executions": total,
            "by_tool": dict(by_tool),
            "by_verdict": dict(by_verdict),
            "avg_duration_ms": round(avg_duration or 0, 2),
        }

    def export_json(self, output_path: str = None) -> str:
        """Export full audit trail as JSON (for SANS submission)."""
        entries = self.query(limit=10000)
        output = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "total_entries": len(entries),
            "entries": entries,
        }
        json_str = json.dumps(output, indent=2, default=str)
        if output_path:
            Path(output_path).write_text(json_str)
        return json_str

    def close(self):
        """Cleanup (no-op for file-based, needed for :memory:)."""
        pass


# ── Singleton for MCP server ──────────────────────────────────────────────────

_logger_instance: Optional[ExecutionLogger] = None


def get_logger(db_path: str = "logs/audit_trail.db") -> ExecutionLogger:
    """Get or create the singleton ExecutionLogger."""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = ExecutionLogger(db_path)
    return _logger_instance
