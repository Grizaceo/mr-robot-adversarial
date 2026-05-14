"""Cybersec Lab Adapter for FIND EVIL! hackathon."""

from pathlib import Path
from typing import List, Dict
import json
import logging

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

class CybersecLabAdapter:
    def __init__(self, config: dict):
        self.lab_path = Path(config["lab_path"])
        self.scenarios_dir = self.lab_path / "scenarios"
        self.logs_dir = self.lab_path / "logs"
        self.reports_dir = self.lab_path / "reports"
        self.observer = None

    def start_monitoring(self, callback):
        """Watch for new YARA/Sigma alerts in real-time."""
        if not WATCHDOG_AVAILABLE:
            logging.warning("watchdog not installed — real-time monitoring disabled")
            return
        self.observer = Observer()
        handler = AlertHandler(callback)
        self.observer.schedule(handler, str(self.reports_dir), recursive=False)
        self.observer.start()

    def get_active_alerts(self) -> List[Dict]:
        """Read current alerts from lab's active_alerts.json."""
        alert_file = self.reports_dir / "active_alerts.json"
        if alert_file.exists():
            with open(alert_file) as f:
                return json.load(f)
        return []

    def trigger_scenario(self, scenario_id: str):
        """Manually trigger a scenario for demo purposes."""
        scenario_file = self.scenarios_dir / f"{scenario_id}.json"
        if scenario_file.exists():
            logging.info(f"Triggered scenario: {scenario_id}")
            return True
        return False

    def log_action(self, response: dict):
        """Log agent actions to the lab's agent_actions.log."""
        log_file = self.lab_path / "logs" / "agent_actions.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(log_file, "a") as f:
            f.write(json.dumps(response) + "\n")

if WATCHDOG_AVAILABLE:
    class AlertHandler(FileSystemEventHandler):
        def __init__(self, callback):
            self.callback = callback

        def on_created(self, event):
            if str(event.src_path).endswith("active_alerts.json"):
                self.callback()
