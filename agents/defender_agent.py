from pydantic import BaseModel
from typing import List, Optional
import yaml
import logging
from datetime import datetime

class ThreatAlert(BaseModel):
    id: str
    source: str  # yara, sigma, system
    severity: str  # critical, high, medium, low
    description: str
    affected_hosts: List[str]
    mitre_technique: Optional[str] = None
    timestamp: str

class DefenderAgent:
    def __init__(self, config_path: str = "cybersec-lab-integration/config.yaml"):
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        self.logger = logging.getLogger("DefenderAgent")
        self.detector = ThreatDetector(self.config["llm"])
        self.orchestrator = ResponseOrchestrator(self.config)
        self.lab_adapter = CybersecLabAdapter(self.config["lab_path"])

    def process_alert(self, alert: ThreatAlert) -> dict:
        """Main entry: analyze and respond to threat."""
        self.logger.info(f"Processing alert {alert.id}")
        analysis = self.detector.analyze(alert)
        response = self.orchestrator.execute(analysis)
        self.lab_adapter.log_action(response)
        return response

class ThreatDetector:
    def __init__(self, llm_config: dict):
        self.llm_config = llm_config
        # Initialize LLM client based on provider
        # TODO: Implement actual LLM initialization

    def analyze(self, alert: dict) -> dict:
        prompt = f"""
        Analyze this cybersecurity threat:
        - Source: {alert['source']}
        - Severity: {alert['severity']}
        - Description: {alert['description']}
        - Affected: {alert['affected_hosts']}
        - MITRE: {alert.get('mitre_technique', 'N/A')}

        Provide:
        1. Confidence score (0-1)
        2. Recommended action (contain/eradicate/recover/escalate)
        3. Additional IoCs to hunt for
        4. Potential impact if not contained
        """
        # Call LLM (implement based on chosen provider)
        # For now, return mock analysis
        return {
            "threat_id": alert["id"],
            "severity": alert["severity"],
            "confidence": 0.92,
            "recommended_action": "contain",
            "additional_iocs": ["process:powershell.exe", "network:external-ip-12345"],
            "impact": "Potential data exfiltration if not contained within 5 minutes"
        }

class ResponseOrchestrator:
    def __init__(self, config: dict):
        self.config = config
        self.actions = []

    def execute(self, analysis: dict) -> dict:
        if analysis["recommended_action"] == "contain":
            for host in analysis.get("iocs", []):
                self.actions.append(f"isolate:{host}")
        else:
            self.actions.append("alert_human")
        return {"status": "success", "actions": self.actions, "timestamp": datetime.now().isoformat()}

class CybersecLabAdapter:
    def __init__(self, lab_path: str):
        self.lab_path = Path(lab_path)

    def log_action(self, response: dict):
        log_file = self.lab_path / "logs" / "agent_actions.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(log_file, "a") as f:
            f.write(json.dumps(response) + "\n")

if __name__ == "__main__":
    agent = DefenderAgent()
    sample_alert = ThreatAlert(
        id="demo-001",
        source="yara",
        severity="high",
        description="Suspicious PowerShell activity detected",
        affected_hosts=["workstation-01"],
        mitre_technique="T1059",
        timestamp=datetime.now().isoformat()
    )
    result = agent.process_alert(sample_alert)
    print(json.dumps(result, indent=2))
