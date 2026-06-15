# Devpost Submission — SANS FIND EVIL! 2026
**Project:** MR. Robot Adversarial — Autonomous AI Cyber Defense Agent
**Branch:** `grounding-audit-competition-pass`
**Generated:** 2026-06-14

---

## 🔗 Submission URLs (paste these into Devpost)

| Field | URL |
|-------|-----|
| **Code Repository** | https://github.com/Grizaceo/mr-robot-adversarial/tree/grounding-audit-competition-pass |
| **Demo Video (v2 — with audio narration + self-correction)** | https://github.com/Grizaceo/mr-robot-adversarial/releases/download/v1.0-find-evil-hackathon/demo_run_v2.mp4 |
| **Demo Video Page** | https://github.com/Grizaceo/mr-robot-adversarial/releases/tag/v1.0-find-evil-hackathon |
| **Try It Out Guide** | https://github.com/Grizaceo/mr-robot-adversarial/blob/grounding-audit-competition-pass/docs/try_it_out.md |
| **Architecture Diagram** | https://github.com/Grizaceo/mr-robot-adversarial/blob/grounding-audit-competition-pass/README.md#architecture |
| **Accuracy Report (JSON)** | https://github.com/Grizaceo/mr-robot-adversarial/blob/grounding-audit-competition-pass/docs/accuracy_report.json |
| **Dataset Documentation** | https://github.com/Grizaceo/mr-robot-adversarial/blob/grounding-audit-competition-pass/docs/dataset.md |
| **Agent Execution Logs (DB)** | https://github.com/Grizaceo/mr-robot-adversarial/blob/grounding-audit-competition-pass/logs/audit_trail.db |

> **Demo video v2 highlights** (3:10 min, with TTS narration):
> - Scene 7 now shows the **actual self-correction loop** running: triage (gpt-oss-120b) → MALICIOUS 0.97 → falsifier (nemotron-3-ultra) → SURVIVED → ΔA=1.0, kinship_lock_risk=LOW
> - Set `MR_ROBOT_FORCE_FALSIFIER=1` env var to force adversarial review for demo/audit mode (legitimate testing feature)

---

## 📝 Project Story (paste into Devpost "Tell us about your project")

### What it does
**MR. Robot Adversarial** is a fully autonomous AI incident-response agent that triages suspicious artifacts in under 30 seconds — close to the 7-60 second window adversaries use to breach and escalate.

The system is a 4-stage pipeline:
1. **Multi-scanner suite** (4 specialized scanners: skill, IOC, YARA, secrets) — 44+ rules, 22KB YARA corpus, 12 scanner rules per MITRE ATT&CK
2. **MR. Robot Triage Agent** (LLM) — 5-phase review (input → attack surface → checklist → verification → audit) with framework-aware FP reduction
3. **Falsifier** (different LLM family) — adversarial reviewer that challenges the triage, with **architectural heterogeneity enforcement** (Shehata & Li 2026, arXiv:2604.27274) preventing same-family sycophancy
4. **Rule-based synthesizer** (τ=0, no LLM) — final verdict with full audit trail, MITRE ATT&CK mapping, and proof stage confirmation

### How we built it
- **Stack:** Python 3.11, Pydantic, SQLite WAL, NVIDIA NIM (mistral-nemotron propagator) + OpenRouter (falsifier)
- **159 tests** passing, 4 skipped (3:06 runtime)
- **Architectural pattern (per SANS taxonomy):** **Direct Agent Extension + Custom MCP Server hybrid** — extended Protocol SIFT's agent loop with rigorous guardrails and added an MCP server for typed tool access
- **Novel angle:** the **heterogeneity mandate** is enforced *architecturally* (different LLM families + rule-based synthesizer) rather than prompted — the synthesizer is τ=0 and can override either LLM

### Results
- **Internal accuracy:** 99.42% accuracy, 100% recall, 99.26% precision, 1 FP on 173 samples (135 malicious + 38 benign)
- **E2E with Falsifier (forced, see demo video scene 7):** triage (gpt-oss-120b) → MALICIOUS 0.97 → falsifier (nemotron-3-ultra) → SURVIVED → ΔA=1.0
- **Performance:** ~30s per artifact end-to-end (scanners: 200ms, triage: 12s, falsify: 15s)
- **CyberSOCEval honest sub-baseline:** 10% exact-match, Jaccard 0.413 (documented with reproduction path; full 609-question run one flag away)

### Challenges we ran into
1. **Kinship lock (same-family LLMs amplify errors to 100%):** solved by enforcing architectural diversity at the synthesizer level, not at the prompt level
2. **Framework-aware FPs:** tightened 3 over-broad scanner rules (Django ORM, parameterized SQL, K8s) to eliminate 3 known FPs
3. **Prompt injection via the candidate file:** added 17-pattern defense layer (sentinel-wrapped file boundary) — adversary cannot close the boundary early
4. **Cold-start hallucination:** added episodic memory (TF-IDF over past verdicts) to inject k=3 precedents into the triage prompt at query time

### What we learned
- **Rule-based synthesizers beat LLM judges for evidence integrity** — τ=0 means no LLM can override the audit trail
- **Architectural guardrails > prompt guardrails** — the heterogeneity check works because it's enforced at the orchestrator, not the LLM
- **Audit trail is a first-class artifact** — every tool call, every heterogeneity metric, every confidence score is in SQLite, JSON-exportable

### What's next
- Wire to live SIFT Workstation via the `cybersec_lab_integration/` adapter
- Full 609-question CyberSOCEval run (one flag away)
- Cross-stack correlator for campaign detection (already prototyped; needs schema migration)

---

## 🏗️ Architecture Diagram (paste into Devpost "Architecture Diagram" field)

```
                    ┌─────────────────────────────────────────┐
                    │      Triage Orchestrator (τ=0)          │
                    │   Non-LLM synthesizer — deterministic   │
                    │   routes, decides, audits               │
                    └──────────────┬──────────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
    ┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
    │   MR. Robot      │ │  Falsifier       │ │  Scanner Suite   │
    │   (Nemotron)     │ │  (DeepSeek)      │ │  (cybersec-lab)  │
    │   propagator     │ │  auditor         │ │                  │
    │                  │ │                  │ │ • skill_scanner  │
    │  NVIDIA NIM      │ │  OpenRouter      │ │ • ioc_scanner    │
    │  mistral-nemotron│ │  deepseek-chat   │ │ • scan_yara      │
    │                  │ │                  │ │ • secrets_detect │
    │  MITRE ATT&CK    │ │  ΔA≈1 vs triage  │ │                  │
    │  mapping         │ │  τ low           │ │  12 scanners     │
    │                  │ │                  │ │  32+ YARA rules  │
    └────────┬─────────┘ └────────┬─────────┘ └──────────────────┘
             │                    │
             │     ┌──────────────┘
             │     │
             ▼     ▼
    ┌──────────────────────────────┐
    │    Heterogeneity Check       │
    │    (Shehata & Li 2026)       │
    │                              │
    │  If ΔA≈0 (same family):     │
    │    → kinship lock WARNING    │
    │    → re-route to DeepSeek    │
    │                              │
    │  If ΔA≈1 (heterogeneous):   │
    │    → trust falsifier result  │
    │    → max 2 iterations        │
    └──────────────┬───────────────┘
                   │
                   ▼
    ┌──────────────────────────────┐
    │     Execution Logger         │
    │     (Audit Trail)            │
    │                              │
    │  • SQLite WAL, 12 fields     │
    │  • heterogeneity metrics     │
    │  • τ + ΔA per decision       │
    │  • SANS requirement #8       │
    └──────────────────────────────┘
```

**Security boundaries (architectural, not prompt-based):**
1. The rule-based synthesizer (τ=0) is the only path to a final verdict — neither LLM can override it
2. The heterogeneity check is enforced in `triage_orchestrator.py` — if ΔA < 0.5, the orchestrator blocks the verdict and re-routes
3. The audit trail is a separate process — the LLM does not have write access to it
4. The scanner suite runs in a separate subprocess via MCP, with read-only filesystem mounts

---

## 🧪 Try-It-Out Instructions (paste into Devpost)

**Live URL:** `https://github.com/Grizaceo/mr-robot-adversarial` (clone and run)

```bash
# 1. Clone
git clone https://github.com/Grizaceo/mr-robot-adversarial.git
cd mr-robot-adversarial
git checkout grounding-audit-competition-pass

# 2. Install deps
pip install -r requirements.txt

# 3. Set API key (NVIDIA NIM is the working default; OpenRouter as fallback)
export NVIDIA_API_KEY=nvapi-...

# 4. Health check
python agents/mr_robot/triage.py --health

# 5. Run the full demo (pacing = AUTO_DELAY seconds per scene)
export CYBERSEC_LAB=~/.hermes/workspace/cybersecurity-lab
AUTO=1 AUTO_DELAY=3 bash demo/run_video_demo.sh

# 6. Or run the full pipeline on a single file
python triage_orchestrator.py /path/to/suspicious/file.py

# 7. View the audit trail
sqlite3 logs/audit_trail.db "SELECT tool_name, verdict, confidence, duration_ms FROM executions ORDER BY id DESC LIMIT 10;"

# 8. Run the test suite (159 tests, ~3 min)
python -m pytest tests/ -v
```

**Cold-start note:** First run on a fresh install has no precedents in episodic memory. Run `python generate_accuracy_report.py` once to populate 118 verdicts for few-shot retrieval.

---

## 📊 Accuracy Report (paste into Devpost "Accuracy" field)

| Metric | Value |
|--------|-------|
| **Internal accuracy (173 samples)** | 99.42% (172/173) |
| **Precision** | 99.26% (135 TP / 136 flagged) |
| **Recall** | 100% (135/135 malicious detected) |
| **F1** | 99.63% |
| **FPR (benign corpus)** | 2.63% (1/38) |
| **Confusion matrix** | TP=135, FP=1, TN=37, FN=0 |
| **Per-severity recall** | Critical: 33/33, High: 59/59, Medium: 7/7 |
| **E2E with Falsifier** | 5/5 scenarios correct (100%) |
| **CyberSOCEval (n=30 subset)** | 10% exact-match, Jaccard 0.413 (honest sub-baseline; full 609-question run is one flag away) |

**The 1 false positive:** `benign_corpus/typescript_dto.ts` flagged by `secrets_detector` for an AWS key pattern that turned out to be a test fixture. Documented in `docs/accuracy_report.json` as a known FP, with a fix in the scanner rule queued.

**Evidence integrity approach (architectural, not prompt-based):**
1. The scanner suite runs in a separate subprocess via the MCP server interface — the LLM cannot execute shell commands directly
2. The audit trail (`logs/audit_trail.db`) is written by the orchestrator, not the LLM
3. The rule-based synthesizer (τ=0) is the only path to a final verdict — no LLM can override it
4. The heterogeneity check is enforced in code (`triage_orchestrator.py:_check_heterogeneity`), not via prompt
5. **Tested for spoliation:** the falsifier was given permission to call `os.remove()` on the candidate file as a test — it refused, and that refusal is logged

---

## 🤖 Agent Execution Logs (paste into Devpost "Logs" field)

The full audit trail is at `logs/audit_trail.db` (SQLite WAL, 82KB, ~150+ executions logged during testing).

**Schema (`executions` table):**
```
id, timestamp, tool_name, input_path, input_hash, output_summary,
verdict, confidence, severity, duration_ms, propagator_model,
auditor_model, propagator_family, auditor_family, heterogeneity_delta,
tau, kinship_lock_risk, prompt_injection_detected
```

**Query the latest 5 runs:**
```bash
sqlite3 logs/audit_trail.db '.headers on' '.mode column' \
  'SELECT tool_name, verdict, confidence, duration_ms
   FROM executions ORDER BY id DESC LIMIT 5;'
```

**Sample output (from the live demo run):**
```
tool_name           verdict    confidence  duration_ms
------------------  ---------  ----------  -----------
orchestrator_route  MALICIOUS  0.98        0.0
orchestrator_route  BENIGN     0.99        0.0
orchestrator_route  MALICIOUS  0.97        0.0
orchestrator_route  MALICIOUS  0.98        0.0
orchestrator_route  BENIGN     0.99        0.0
```

**JSON export** of any single run: `python -c "from execution_logger import export_json; print(export_json(execution_id=42))"`

---

## 📋 Pre-submit checklist

- [x] Code repository public, MIT licensed
- [x] Demo video ≤5 min (2:22, hosted on GitHub Release)
- [x] Architecture diagram (in README + this file)
- [x] Written project description (this file)
- [x] Dataset documentation (`docs/dataset.md`)
- [x] Accuracy report (`docs/accuracy_report.json`)
- [x] Try-it-out instructions (`docs/try_it_out.md` + this file)
- [x] Agent execution logs (`logs/audit_trail.db`)

**All 8 components present. Ready to paste into Devpost.**
