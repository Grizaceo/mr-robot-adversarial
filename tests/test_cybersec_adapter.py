"""Tests for CybersecLabAdapter."""

import os
from pathlib import Path
from cybersec_lab_integration.adapter import CybersecLabAdapter

def _lab_path():
    """Resolve lab path: $CYBERSEC_LAB in container, ~/.hermes/... on host."""
    env = os.environ.get("CYBERSEC_LAB")
    if env:
        return env
    return str(Path.home() / ".hermes" / "workspace" / "cybersecurity-lab")

def test_adapter_initialization():
    config = {"lab_path": _lab_path()}
    adapter = CybersecLabAdapter(config)
    assert adapter.lab_path.exists()

def test_get_active_alerts(tmp_path):
    # Create a fake reports directory with active_alerts.json
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    alerts_file = reports_dir / "active_alerts.json"
    alerts_file.write_text('[{"id": "test", "source": "yara"}]')
    
    config = {"lab_path": str(tmp_path)}
    adapter = CybersecLabAdapter(config)
    # Override reports_dir for test
    adapter.reports_dir = reports_dir
    alerts = adapter.get_active_alerts()
    assert len(alerts) == 1
    assert alerts[0]["id"] == "test"
