"""Tests for CybersecLabAdapter."""

import pytest
from cybersec-lab-integration.adapter import CybersecLabAdapter

def test_adapter_initialization():
    config = {"lab_path": "/home/gris/.hermes/workspace/cybersecurity-lab"}
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
