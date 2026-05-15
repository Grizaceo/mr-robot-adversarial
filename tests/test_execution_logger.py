import json
from pathlib import Path

from execution_logger import ExecutionLogger
from mcp_tools import _run_scanner


def test_execution_logger_initializes_wal(tmp_path):
    db = tmp_path / "audit.db"
    logger = ExecutionLogger(db)
    with logger.connect() as conn:
        mode = conn.execute("PRAGMA journal_mode;").fetchone()[0].lower()
    assert mode == "wal"


def test_execution_logger_logs_basic_event(tmp_path):
    db = tmp_path / "audit.db"
    logger = ExecutionLogger(db)
    logger.log(tool_name="scan_file", input_data={"filepath": "x"}, output_data={"verdict": "BENIGN"}, duration_ms=12.3)
    with logger.connect() as conn:
        row = conn.execute("SELECT tool_name, output_json FROM executions ORDER BY id DESC LIMIT 1").fetchone()
    assert row[0] == "scan_file"
    assert json.loads(row[1])["verdict"] == "BENIGN"


def test_run_scanner_returns_structured_error_for_missing_scanner(monkeypatch):
    result = _run_scanner("does_not_exist", ["/tmp/nope.py"])
    assert result["error"] == "scanner_not_found"
    assert result["findings"] == []
