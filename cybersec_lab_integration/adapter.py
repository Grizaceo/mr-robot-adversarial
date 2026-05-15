#!/usr/bin/env python3
"""Cybersec Lab Adapter — Bridge to cybersecurity-lab (simplified)."""

from pathlib import Path
from typing import List, Dict
import json


class CybersecLabAdapter:
    def __init__(self, config: dict):
        self.lab_path = Path(config.get("lab_path", ""))
        self.scenarios_dir = self.lab_path / "scenarios"
        self.logs_dir = self.lab_path / "logs"
        self.reports_dir = self.lab_path / "reports"

    def get_active_alerts(self) -> List[Dict]:
        alert_file = self.reports_dir / "active_alerts.json"
        if alert_file.exists():
            return json.loads(alert_file.read_text())
        return []

    def trigger_scenario(self, scenario_id: str) -> bool:
        return (self.scenarios_dir / f"{scenario_id}.json").exists()

    def log_action(self, response: dict):
        log_file = self.lab_path / "logs" / "agent_actions.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(log_file, "a") as f:
            f.write(json.dumps(response) + "\n")
