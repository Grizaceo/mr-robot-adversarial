# FIND EVIL! — Autonomous Cyber Defense Agent System

**Hackathon:** FIND EVIL! AI threats strike in minutes
**Deadline:** June 15, 2026
**Team:** DAVI + Cristóbal
**Status:** Core implementation complete, accuracy report running

## Mission

Build an autonomous AI agent system that detects, analyzes, and responds to
cybersecurity threats in real-time — using the mature `cybersecurity-lab`
infrastructure already built.

## Architecture

```
File → Scanners → MR. Robot Triage → Falsifier Review → Final Report
                                    ↓ (if FALSIFIED)
                              Self-Correction Loop (max 3 iterations)
```

### Components

| Component | File | Lines | Status |
|-----------|------|-------|--------|
| MCP Server | `mcp_server.py` | 483 | ✅ Functional |
| MR. Robot Triage | `agents/mr_robot/triage.py` | 538 | ✅ Functional |
| TriageFalsifier | `triage_falsifier.py` | 312 | ✅ Functional |
| Execution Logger | `execution_logger.py` | 247 | ✅ Functional |
| Scanner Suite | (cybersec-lab) | — | ✅ Integrated |

### MCP Tools

1. **scan_file** — Run all 4 scanners on a file
2. **triage_artifact** — AI-powered triage with MITRE mapping
3. **falsify_triage** — Triage + Falsifier self-correction loop
4. **get_baseline** — Retrieve scenario baseline data
5. **health** — Component status check

## Quick Start

```bash
# 1. Clone and enter
cd find-evil-hackathon

# 2. Install dependencies
pip install mcp pydantic pyyaml

# 3. Set API key (NVIDIA NIM)
# Add to ~/.hermes/.env: NVIDIA_API_KEY=nvapi-...

# 4. Run health check
python -m agents.mr_robot.triage --health

# 5. Run accuracy report
python generate_accuracy_report.py

# 6. Run demo
./demo/run_demo.sh
```

## Test Results

### E2E Test (5 scenarios)
- bind_shell.py: MALICIOUS (0.95 conf) ✅
- reverse_shell.sh: MALICIOUS (0.95 conf) ✅
- npm_worm.js: MALICIOUS (0.95 conf, 2 iterations) ✅
- safe_app.py: BENIGN (0.99 conf) ✅
- yaml_rce.yaml: MALICIOUS (0.95 conf) ✅

**Result: 5/5 correct (100%)**

### Accuracy Report
- Running on full test-corpus (21 files: 14 malicious, 7 benign)
- See `docs/accuracy_report.md` for full results

## LLM Provider

- **Primary:** NVIDIA NIM (mistralai/mistral-nemotron)
- **Fallback 1:** Ollama Cloud (kimi-k2.5)
- **Fallback 2:** OpenRouter (gpt-oss-120b:free)
- **API Key:** Read from `~/.hermes/.env`

## Related Repositories

- `~/.hermes/workspace/cybersecurity-lab/` — Scanner suite + 100 scenarios
- `~/.hermes/workspace/repos/kiss_discovery_engine/` — FastTracker (audit trail base)
- `~/.hermes/workspace/repos/AGENTIC_RIEMANN_TROPICAL/` — Falsifier pattern

---

*Last updated: 2026-05-14 by DAVI*
