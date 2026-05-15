# BLUEPRINT — MR. Robot Adversarial

## Goal

Build a working AI agent system that autonomously defends against cyber threats,
integrating with the existing `cybersecurity-lab` to demonstrate real-world impact.

## Status: READY FOR SUBMISSION (pending demo video)

**Deadline:** June 15, 2026 (31 days remaining as of 2026-05-15)

### Last review (2026-05-15)
End-to-end repo review identified and fixed two credibility gaps:
1. Accuracy report now includes a **benign control set** (19 samples) so
   precision/FPR are real numbers, not artifacts of testing only positives.
2. Heterogeneity Mandate now references both the primary source (Shehata &
   Li 2026) and supporting prior literature (Du 2023, Wang 2022, Liang 2023,
   Sharma 2023) so reviewers can triangulate.
See `CHANGELOG.md` for details.

## What We Built

### Core Pipeline
```
File → Scanners → MR. Robot Triage → Falsifier Review → Final Report
                                    ↓ (if FALSIFIED)
                              Self-Correction Loop (max 3 iterations)
```

### Components

1. **MCP Server** (`mcp_server.py`, 483 lines)
   - 5 tools: scan_file, triage_artifact, falsify_triage, get_baseline, health
   - stdio transport (MCP protocol)
   - Integrated audit trail logging

2. **MR. Robot Triage Agent** (`agents/mr_robot/triage.py`, 538 lines)
   - AI-powered triage with MITRE ATT&CK mapping
   - Provider: NVIDIA NIM (mistralai/mistral-nemotron) + 2 fallbacks
   - Structured JSON output: verdict, confidence, severity, findings, actions
   - Scanner correlation (skill, ioc, yara, secrets)

3. **TriageFalsifier** (`triage_falsifier.py`, 312 lines)
   - Adversarial reviewer — challenges MR. Robot's findings
   - Self-correction loop with confidence threshold (0.7)
   - Max 3 iterations per file

4. **Execution Logger** (`execution_logger.py`, 247 lines)
   - SQLite WAL audit trail (SANS requirement #8)
   - 12 fields: tool_name, input, output, duration, verdict, severity, confidence
   - Query interface + JSON export

5. **Scanner Suite** (from cybersecurity-lab)
   - skill_scanner: 32+ YARA-like rules + AST + prompt injection
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

### Accuracy Report (118 samples — 99 malicious + 19 benign)
- Accuracy: 97.5%
- Precision: 97.1%
- Recall: 100%
- F1: 0.985
- FPR: 15.8% (3/19 benign flagged — `k8s_deployment.yaml`,
  `parameterized_sql.py`, `safe_server.js`)
- See `docs/accuracy_report.json` for full results

## Submission Requirements Checklist

| # | Requirement | Status | Notes |
|---|------------|--------|-------|
| 1 | Repo GitHub público | ✅ | https://github.com/Grizaceo/mr-robot-adversarial |
| 2 | Demo video (3 min) | ❌ | Not started |
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
5. 🔄 Accuracy Report (running)
6. ⬜ SIFT Workstation + Protocol SIFT
7. ⬜ Demo video
8. ⬜ Try-it-out instructions
9. ⬜ Push to public GitHub
10. ⬜ Submit before June 15
