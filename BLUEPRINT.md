# BLUEPRINT — MR. Robot Adversarial

## Goal

Build a working AI agent system that autonomously defends against cyber threats,
integrating with the existing `cybersecurity-lab` to demonstrate real-world impact.

## Status: SUBMITTED

**Deadline:** June 15, 2026 (30 days remaining as of 2026-05-16)

### Last review (2026-05-16)
End-to-end repo review, ruff hygiene pass, and metrics sync. All tests pass.

### Accuracy Report (173 samples — 135 malicious + 38 benign)
- Accuracy: 99.42%
- Precision: 99.26%
- Recall: 100.0%
- F1: 0.9963
- FPR: 2.63% (1/38 benign flagged)
- See `docs/accuracy_report.json` for full results

## What We Built

### Core Pipeline
```
File → Scanners → MR. Robot Triage → Falsifier Review → Final Report
                                    ↓ (if FALSIFIED)
                              Self-Correction Loop (max 2 iterations)
```

### Components

1. **MCP Server** (`mcp_server.py`, 246 lines)
   - 5 tools: scan_file, triage_artifact, falsify_triage, get_baseline, health
   - stdio transport (MCP protocol)
   - Integrated audit trail logging

2. **MR. Robot Triage Agent** (`agents/mr_robot/triage.py`, 844 lines)
   - AI-powered triage with MITRE ATT&CK mapping
   - Provider: NVIDIA NIM (mistralai/mistral-nemotron) + 2 fallbacks
   - Structured JSON output: verdict, confidence, severity, findings, actions
   - Scanner correlation (skill, ioc, yara, secrets)

3. **TriageFalsifier** (`triage_falsifier.py`, 365 lines)
   - Adversarial reviewer — challenges MR. Robot's findings
   - Self-correction loop with confidence threshold (0.7)
   - Max 2 iterations per file

4. **Execution Logger** (`execution_logger.py`, 247 lines)
   - SQLite WAL audit trail (SANS requirement #8)
   - 12 fields: tool_name, input, output, duration, verdict, severity, confidence
   - Query interface + JSON export

5. **Scanner Suite** (from cybersecurity-lab)
   - skill_scanner: 44 detection rules (YARA-like + AST + prompt injection)
   - ioc_scanner: 12 URLs, 6 domains, 10 heuristic patterns
   - scan_yara: davi_malware_rules.yar (22KB, custom rules)
   - secrets_detector: hardcoded credentials, API keys

## Test Results

### E2E Test (5 scenarios)
| File | Expected | Predicted | Confidence | Iterations |
|------|----------|-----------|------------|------------|
| bind_shell.py | MALICIOUS | MALICIOUS | 0.95 | 1 |
| reverse_shell.sh | MALICIOUS | MALICIOUS | 0.95 | 1 |
| mr_robot_npm_worm.js | MALICIOUS | MALICIOUS | 0.95 | 2 |
| safe_app.py | BENIGN | BENIGN | 0.99 | 1 |
| mr_robot_yaml_rce.yaml | MALICIOUS | MALICIOUS | 0.95 | 1 |

**Result: 5/5 correct (100%)**

### Accuracy Report (173 samples — 135 malicious + 38 benign)
- Accuracy: 99.42%
- Precision: 99.26%
- Recall: 100.0%
- F1: 0.9963
- FPR: 2.63% (1/38 benign flagged)
- See `docs/accuracy_report.json` for full results

## Submission Requirements Checklist

| # | Requirement | Status | Notes |
|---|------------|--------|-------|
| 1 | Repo GitHub publico | ✅ | https://github.com/Grizaceo/mr-robot-adversarial |
| 2 | Demo video (3 min) | ⏳ | Guion + SRT + OBS checklist listos en `demo/` |
| 3 | Text description | ✅ | BLUEPRINT + README + architecture updated |
| 4 | Architecture diagram | ✅ | `docs/architecture.md` updated |
| 5 | Working code | ✅ | All components functional |
| 6 | Dataset documentation | ✅ | `docs/accuracy_report.md` + `docs/e2e_test_results.md` |
| 7 | Try-it-out instructions | ✅ | `docs/try_it_out.md` created |
| 8 | Agent execution logs | ✅ | Audit trail functional |

## Next Steps

1. ✅ ~~MR. Robot Triage Agent~~
2. ✅ ~~MCP Server~~
3. ✅ ~~Execution Logger~~
4. ✅ ~~TriageFalsifier + Self-Correction~~
5. ✅ ~~Accuracy Report (100% / 0% FPR)~~
6. ⬜ SIFT Workstation + Protocol SIFT — **deferred** (out of scope for this submission; WSL bridge prototype and migration path documented in `docs/sift_integration.md` for future work)
7. ⬜ Demo video
8. ✅ ~~Push to public GitHub~~
9. ⬜ Submit before June 15
