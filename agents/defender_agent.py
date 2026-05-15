#!/usr/bin/env python3
"""DefenderAgent — Main orchestrator (skeleton, replaced by MCP server in practice)."""

from pydantic import BaseModel
from typing import List, Optional
import json, logging
from datetime import datetime
from pathlib import Path

from agents.threat_detector import ThreatDetector
from agents.response_orchestrator import ResponseOrchestrator
from cybersec_lab_integration.adapter import CybersecLabAdapter


class ThreatAlert(BaseModel):
    id: str
    source: str
    severity: str
    description: str
    affected_hosts: List[str]
    mitre_technique: Optional[str] = None
    timestamp: str


class DefenderAgent:
    def __init__(self, config_path: str = "cybersec_lab_integration/config.yaml"):
        self.logger = logging.getLogger("DefenderAgent")
        self.config = {"llm": {}, "lab_path": "", "agent": {}, "features": {}}
        self.detector = ThreatDetector(self.config["llm"])
        self.orchestrator = ResponseOrchestrator(self.config)
        self.lab_adapter = CybersecLabAdapter(self.config)

    def process_alert(self, alert: ThreatAlert) -> dict:
        a = alert.model_dump()
        return {
            "threat_id": a["id"],
            "severity": a["severity"],
            "confidence": 0.92,
            "recommended_action": "contain",
            "iocs": a.get("affected_hosts", []),
            "status": "success",
            "actions": [f"isolate:{h}" for h in a.get("affected_hosts", [])],
            "timestamp": datetime.now().isoformat(),
        }
