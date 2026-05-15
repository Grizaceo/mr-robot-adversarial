# FIND EVIL! — Autonomous AI Cyber Defense Agent

> **SANS Institute Hackathon 2026** — AI threats strike in minutes. Can your defense keep up?

An autonomous AI agent system that detects, analyzes, and responds to cybersecurity
threats in real-time — combining static analysis scanners with LLM-powered triage
and adversarial self-correction.

## The Problem

An adversary AI can go from initial access to full domain control in **under 8 minutes**
(CrowdStrike: fastest breakout time 7 min). Meanwhile, human analysts are still
searching for CLI flags during an active incident.

**FIND EVIL!** closes that gap: automated scanning → AI triage → adversarial review
→ self-correction, all in under 30 seconds per file.

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │           MCP Server (stdio)             │
                    │  scan_file │ triage_artifact │ falsify   │
                    │  get_baseline │ health                     │
                    └──────────────┬──────────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
    ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
    │   MR. Robot      │ │  Falsifier       │ │  Scanner Suite   │
    │   Triage Agent   │ │  (Adversarial    │ │  (cybersec-lab)  │
    │                  │ │   Reviewer)      │ │                  │
    │  NVIDIA NIM      │ │  NVIDIA NIM      │ │ • skill_scanner  │
    │  (primary)       │ │  (same model)    │ │ • ioc_scanner    │
    │  + 2 fallbacks   │ │                  │ │ • scan_yara      │
    │                  │ │  Challenges      │ │ • secrets_detect │
    │  MITRE ATT&CK    │ │  each finding,   │ │                  │
    │  mapping         │ │  finds false     │ │  100+ scenarios  │
    │                  │ │  positives       │ │  32+ YARA rules  │
    └──────────────────┘ └──────────────────┘ └──────────────────┘
              │                    │
              └────────┬───────────┘
                       ▼
              ┌──────────────────┐
              │ Self-Correction  │
              │ Loop             │
            ┌─┤                  ├─┐
            │ │ If FALSIFIED:   │ │
            │ │ re-run triage   │ │
            │ │ with counter-   │ │
            │ │ argument        │ │
            │ │ (max 3 iters)   │ │
            │ └──────────────────┘ │
            └──────────────────────┘
                       │
                       ▼
              ┌──────────────────┐
              │ Execution Logger │
              │ (Audit Trail)    │
            ┌─┤                  ├─┐
            │ │ SQLite WAL       │ │
            │ │ 12 fields        │ │
            │ │ SANS req #8      │ │
            │ └──────────────────┘ │
            └──────────────────────┘
```

## Key Features

### 🔍 Multi-Scanner Analysis
Four specialized scanners analyze each file:
- **skill_scanner** — 32+ YARA-like rules, AST analysis, prompt injection detection
- **ioc_scanner** — 12 malicious URLs, 6 domains, 10 heuristic patterns
- **scan_yara** — Custom YARA rules (22KB) for C2 infrastructure and backdoor primitives
- **secrets_detector** — Hardcoded credentials, API keys, tokens

### 🤖 MR. Robot Triage Agent
LLM-powered analysis that goes beyond pattern matching:
- Correlates scanner findings with actual code behavior
- Maps to MITRE ATT&CK techniques
- Assigns confidence scores (0.0–1.0)
- Recommends specific incident response actions
- Detects scanner gaps (e.g., false negatives)

### 🔄 Falsifier + Self-Correction
An adversarial reviewer that plays devil's advocate:
- Challenges each finding: "What if this is a false positive?"
- Proposes alternative benign explanations
- If it finds genuine weaknesses, MR. Robot re-runs with the counter-argument
- Iterates up to 3 times until the triage survives falsification

### 📋 Execution Logger (Audit Trail)
Every tool call is logged with full context:
- Tool name, input arguments, output results
- Duration, verdict, severity, confidence
- SQLite WAL mode for concurrent writes
- JSON export for SANS submission (Requirement #8)

## Results

### Accuracy Evaluation (21 files: 14 malicious, 7 benign)

| Metric | Value |
|--------|-------|
| **Accuracy** | 90.5% (19/21) |
| **Precision** | 92.9% (13/14 predicted malicious were correct) |
| **Recall** | 92.9% (13/14 actual malicious detected) |
| **F1 Score** | 0.9286 |
| **False Positive Rate** | 14.3% (1/7 benign flagged) |

### E2E Test (5 scenarios with Falsifier)

| File | Expected | Predicted | Confidence | Iterations |
|------|----------|-----------|------------|------------|
| bind_shell.py | MALICIOUS | MALICIOUS | 0.95 | 1 |
| reverse_shell.sh | MALICIOUS | MALICIOUS | 0.95 | 1 |
| mr_robot_npm_worm.js | MALICIOUS | MALICIOUS | 0.95 | 2 |
| safe_app.py | BENIGN | BENIGN | 0.99 | 1 |
| mr_robot_yaml_rce.yaml | MALICIOUS | MALICIOUS | 0.95 | 1 |

**Result: 5/5 correct (100%)**

### Performance

| Operation | Avg Duration |
|-----------|-------------|
| Scan (4 scanners) | ~200ms |
| Triage (MR. Robot) | ~12s |
| Falsification | ~15s |
| Full pipeline (with correction) | ~30s |

## Quick Start

### Prerequisites
- Python 3.11+
- NVIDIA NIM API key (free at [build.nvidia.com](https://build.nvidia.com))
- Or Ollama Cloud / OpenRouter as fallback

### Installation
```bash
git clone https://github.com/Grizaceo/mr-robot-adversarial.git
cd mr-robot-adversarial
pip install mcp pydantic pyyaml
```

### Set API Key
```bash
# NVIDIA NIM (recommended)
export NVIDIA_API_KEY=nvapi-...

# Or Ollama Cloud
export OLLAMA_API_KEY=...

# Or OpenRouter
export OPENROUTER_API_KEY=sk-or-...
```

### Run
```bash
# Health check
python agents/mr_robot/triage --health

# Scan a file
python -c "
from mcp_server import scan_file
import json
result = scan_file('/path/to/file.py')
print(json.dumps(json.loads(result), indent=2))
"

# Full triage with self-correction
python -c "
from triage_falsifier import run_self_correction_loop
import json
report = run_self_correction_loop('/path/to/file.py')
print(json.dumps(report, indent=2, default=str))
"

# Generate accuracy report
python accuracy_report.py
```

### Docker
```bash
docker-compose up
```

## Project Structure

Note: the original pre-MCP skeleton prototypes were archived under `legacy/agents/` after the repo standardized on the active MR. Robot + MCP + Falsifier pipeline.

```
mr-robot-adversarial/
├── agents/
│   └── mr_robot/
│       └── triage.py          # MR. Robot Triage Agent
├── cybersec_lab_integration/
│   ├── adapter.py             # Bridge to cybersecurity-lab
│   └── config.yaml            # Lab configuration
├── docs/
│   ├── architecture.md        # Detailed architecture
│   ├── accuracy_report.json   # Full accuracy results
│   ├── e2e_test_results.md    # E2E test results
│   ├── sift_integration.md    # SIFT integration status
│   ├── submission_requirements.md # SANS requirements
│   └── try_it_out.md          # Step-by-step guide
├── legacy/
│   └── agents/                # Archived pre-MCP skeleton prototypes
├── mcp_server.py              # MCP Server with 5 tools
├── mcp_tools.py               # Shared scanner/triage helpers
├── triage_falsifier.py        # Falsifier + self-correction
├── execution_logger.py        # Audit trail logger
├── accuracy_report.py         # Accuracy report viewer
├── demo/                      # Demo scenarios and scripts
├── tests/                     # Active smoke/unit tests
├── BLUEPRINT.md               # Project blueprint
├── Dockerfile                 # Container definition
├── docker-compose.yml         # Docker orchestration
└── requirements.txt           # Python dependencies
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `scan_file` | Run all 4 scanners on a file |
| `triage_artifact` | AI-powered triage with MITRE mapping |
| `falsify_triage` | Triage + Falsifier self-correction loop |
| `get_baseline` | Retrieve scenario baseline data |
| `health` | Component status check |

## LLM Strategy

- **Primary:** NVIDIA NIM (mistralai/mistral-nemotron) — best for security reasoning
- **Fallback 1:** Ollama Cloud (kimi-k2.5)
- **Fallback 2:** OpenRouter (gpt-oss-120b:free + 5 more)
- **Temperature:** 0.3 (deterministic triage)
- **Max tokens:** 4096

## SANS Submission Requirements

| # | Requirement | Status |
|---|------------|--------|
| 1 | Public GitHub repository | ✅ |
| 2 | Demo video (≤3 min) | ⬜ Pending |
| 3 | Text description | ✅ |
| 4 | Architecture diagram | ✅ |
| 5 | Working code | ✅ |
| 6 | Dataset documentation | ✅ |
| 7 | Try-it-out instructions | ✅ |
| 8 | Agent execution logs | ✅ |

## Related Work

- [cybersecurity-lab](~/.hermes/workspace/cybersecurity-lab/) — Scanner suite + 100 adversarial scenarios
- [KISS Discovery Engine](~/.hermes/workspace/repos/kiss_discovery_engine/) — FastTracker (audit trail base)
- [AGENTIC_RIEMANN_TROPICAL](~/.hermes/workspace/repos/AGENTIC_RIEMANN_TROPICAL/) — Falsifier pattern

## License

MIT

---

*Built by DAVI + Cristóbal for the SANS FIND EVIL! Hackathon 2026*
