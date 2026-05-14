# Architecture Document — FIND EVIL! Submission

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    FIND EVIL! Defender Agent               │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Defender   │→│  Threat      │→│  Response        │  │
│  │  Agent       │  │  Detector    │  │  Orchestrator    │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              Cybersec Lab Adapter (Bridge)                │
├─────────────────────────────────────────────────────────────┤
│  • Reads: ~/.hermes/workspace/cybersecurity-lab/reports/ │
│  • Writes: ~/.hermes/workspace/cybersecurity-lab/logs/   │
│  • Triggers: Scenario evaluation                         │
└─────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

| Component | Responsibility | Input | Output |
|-----------|----------------|-------|--------|
| DefenderAgent | Orchestrate workflow | ThreatAlert | Response dict |
| ThreatDetector | LLM-based analysis | Alert data | Analysis with confidence |
| ResponseOrchestrator | Execute actions | Analysis | Actions taken |
| CybersecLabAdapter | Lab integration | Config | File/SSE bridge |

## Data Formats

### ThreatAlert (Pydantic model)
```python
class ThreatAlert(BaseModel):
    id: str
    source: str  # yara, sigma, system
    severity: str  # critical, high, medium, low
    description: str
    affected_hosts: List[str]
    mitre_technique: Optional[str]
    timestamp: str
```

### Lab Integration

- **Input:** `cybersecurity-lab/reports/active_alerts.json` (list of alerts)
- **Output:** `cybersec-lab/logs/agent_actions.log` (append JSON per action)
- **Trigger:** File system watcher on `reports/` directory

## LLM Strategy

- Use any available model (DeepSeek, Claude, Gemini, local Llama)
- Prompt engineering for threat analysis (see docs/prompts.md if needed)
- Keep prompts short to reduce latency (< 2s response desired)

## Evaluation Metrics

For judging:
- **Time to Detect → Respond:** < 30 seconds end-to-end
- **Accuracy:** False positive rate < 5%
- **Coverage:** Handle at least 3 distinct attack vectors (YARA, Sigma, anomaly)
- **Explainability:** Show LLM reasoning traces in demo

## Deployment

- Containerized with Docker (single service)
- Config via `cybersec-lab-integration/config.yaml`
- No database required (file-based)
