# Architecture Document — FIND EVIL! Submission

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                     FIND EVIL! Agent System                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    MCP Server (stdio)                         │  │
│  │  ┌─────────────┐ ┌──────────────┐ ┌───────────────────────┐ │  │
│  │  │ scan_file   │ │triage_artifact│ │ falsify_triage        │ │  │
│  │  │             │ │              │ │ (self-correction loop)│ │  │
│  │  └──────┬──────┘ └──────┬───────┘ └───────────┬───────────┘ │  │
│  │         │               │                      │             │  │
│  │  ┌──────┴───────────────┴──────────────────────┴───────────┐ │  │
│  │  │              Execution Logger (audit trail)              │ │  │
│  │  │         SQLite WAL — SANS Requirement #8                │ │  │
│  │  └─────────────────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────┘ │
│                              │                                      │
│              ┌───────────────┼───────────────┐                     │
│              ▼               ▼               ▼                     │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐          │
│  │   MR. Robot  │ │  Falsifier   │ │  Scanner Suite   │          │
│  │   Triage     │ │  (adversarial│ │  (cybersec-lab)  │          │
│  │   Agent      │ │   reviewer)  │ │                  │          │
│  │              │ │              │ │ • skill_scanner  │          │
│  │  NVIDIA NIM  │ │  NVIDIA NIM  │ │ • ioc_scanner    │          │
│  │  (primary)   │ │  (same)      │ │ • scan_yara      │          │
│  │  +2 fallbacks│ │              │ │ • secrets_detect │          │
│  └──────────────┘ └──────────────┘ └──────────────────┘          │
│                              │                                      │
│                              ▼                                      │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │              Cybersecurity Lab Integration                    │  │
│  │  • Reads: cybersecurity-lab/reports/active_alerts.json       │  │
│  │  • Scans: cybersecurity-lab/test-corpus/ (21 labeled files)  │  │
│  │  • Rules: cybersecurity-lab/scanners/davi_malware_rules.yar  │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

| Component | Responsibility | Input | Output |
|-----------|----------------|-------|--------|
| MCP Server | Tool orchestration, audit logging | Tool calls | JSON responses + audit trail |
| MR. Robot | AI-powered triage with MITRE mapping | File + scanner findings | Triage report (verdict, confidence, severity) |
| Falsifier | Adversarial review of triage reports | Triage report + code | FalsificationResult (SURVIVED/FALSIFIED) |
| Self-Correction | Iterative improvement loop | FalsificationResult | Updated triage with counter-arguments |
| Scanner Suite | Static analysis (4 scanners) | File path | Findings (IOCs, YARA, secrets, skills) |
| Execution Logger | Audit trail (SANS req #8) | All tool calls | SQLite WAL database |

## Data Flow

```
File → [Scanners] → Findings → [MR. Robot] → Triage Report
                                               ↓
                                         [Falsifier]
                                               ↓
                                    FalsificationResult
                                               ↓
                                    ┌──────────┴──────────┐
                                    │ SURVIVED │ FALSIFIED │
                                    ↓          ↓
                               Final    Re-run with
                               Report   counter-argument
                                         (max 3 iterations)
```

## LLM Strategy

- **Primary:** NVIDIA NIM (mistralai/mistral-nemotron)
- **Fallback 1:** Ollama Cloud (kimi-k2.5)
- **Fallback 2:** OpenRouter (gpt-oss-120b:free + 5 more)
- **API Key:** Read from `~/.hermes/.env`
- **Temperature:** 0.3 (deterministic triage)
- **Max tokens:** 4096

## Self-Correction Loop

1. Run scanners → get findings
2. Run MR. Robot triage → get report (verdict, confidence)
3. If confidence ≥ 0.7 and verdict is clear → run Falsifier once
4. If Falsifier FALSIFIES → re-run MR. Robot with counter-argument
5. Repeat up to 3 iterations
6. Log all iterations to audit trail

## Evaluation Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Accuracy | > 90% | TBD (running) |
| Precision | > 85% | TBD |
| Recall | > 90% | TBD |
| False Positive Rate | < 5% | TBD |
| F1 Score | > 0.85 | TBD |
| Avg triage time | < 30s | ~25s |
| End-to-end (with falsifier) | < 60s | ~30s |

## Deployment

- Python 3.11+, no database required (SQLite for audit)
- Dependencies: mcp, pydantic, pyyaml, requests
- Config via `cybersec_lab_integration/config.yaml`
- Docker support (Dockerfile + docker-compose.yml)
- Run: `python mcp_server.py` (stdio transport)
