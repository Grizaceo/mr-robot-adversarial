"""Integration tests for FIND EVIL! agent system."""

import pytest
from agents.defender_agent import DefenderAgent, ThreatAlert

def test_defender_agent_initialization():
    agent = DefenderAgent()
    assert agent.config is not None
    assert agent.detector is not None
    assert agent.orchestrator is not None
    assert agent.lab_adapter is not None

def test_threat_alert_processing():
    agent = DefenderAgent()
    alert = ThreatAlert(
        id="test-001",
        source="yara",
        severity="high",
        description="Test malware detection",
        affected_hosts=["test-host"],
        mitre_technique="T1059",
        timestamp="2026-05-14T00:00:00Z"
    )
    result = agent.process_alert(alert)
    assert result["status"] == "success"
    assert len(result["actions"]) > 0

# TODO: Add more tests:
# - Adapter reads actual lab alerts
# - Response actions execute correctly
# - End-to-end demo runs in < 5 minutes
