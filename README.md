# MR. Robot Adversarial — Autonomous AI Cyber Defense Agent

> **SANS Institute FIND EVIL! Hackathon 2026** — AI threats strike in minutes. Can your defense keep up?

An autonomous AI agent system that detects, analyzes, and responds to cybersecurity
threats in real-time — combining static analysis scanners with LLM-powered triage
and adversarial self-correction.

## The Problem

Adversary AI tools (Microsoft MDASH, Claude Mythos) operate at machine speed with
100+ specialised agents, 88.45% CyberGym accuracy, and full RCE-chain generation.
Human analysts still spend minutes searching for CLI flags during an active incident.

**MR. Robot Adversarial** addresses the narrowest defensible slice of that asymmetry:
per-file triage with verifiable heterogeneity, end-to-end audit trail, and
zero-FP detection — all in under 30 seconds per artifact.

## Architecture

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

> **Heterogeneity Mandate:** Per *Shehata & Li (2026),
> [arXiv:2604.27274](https://arxiv.org/abs/2604.27274)*, the Falsifier
> (auditor) must be architecturally different from MR. Robot (propagator).
> Same-family agents produce τ≈1 → Logic Saturation → 100% error. Using
> DeepSeek as the falsifier ensures ΔA≈1 and τ low. Reinforced by prior
> work on multi-agent diversity (Du 2023, Liang 2023) and LLM sycophancy
> (Sharma 2023). See [`docs/heterogeneity_mandate.md`](docs/heterogeneity_mandate.md).



## Key Features

### 🔍 Multi-Scanner Analysis
Four specialized scanners analyze each file:
- **skill_scanner** — 44 detection rules (YARA-like + AST + prompt injection + ClawDefender patterns)
- **ioc_scanner** — 12 malicious URLs, 6 domains, 10 heuristic patterns
- **scan_yara** — Custom YARA rules (22KB) for C2 infrastructure and backdoor primitives
- **secrets_detector** — Hardcoded credentials, API keys, tokens

### 🤖 MR. Robot Triage Agent (v2 — Mellea-powered)
LLM-powered analysis with rigorous 5-phase review workflow (adapted from IBM Research Mellea Skills Compiler):
- **Phase 1 — Input Gathering:** Reads full file, lists all inputs reviewed
- **Phase 2 — Attack Surface Mapping:** Identifies all user inputs, DB queries, auth checks, sessions, external calls, crypto ops, file I/O
- **Phase 3 — Security Checklist:** 12-category OWASP-style checklist (injection, XSS, auth, authz, CSRF, race conditions, session, crypto, info disclosure, DoS, business logic, supply chain)
- **Phase 4 — Verification:** Traces data flow, checks framework protections, verifies not already handled
- **Phase 5 — Pre-Conclusion Audit:** Lists files reviewed, checklist items checked, areas not verified

**Confidence levels (HIGH/MEDIUM/LOW):**
- HIGH = vulnerable pattern + attacker-controlled input confirmed → REPORT
- MEDIUM = vulnerable pattern, input source unclear → NOTE
- LOW = theoretical/best practice → DO NOT REPORT

**Framework-aware false positive reduction:**
- Recognizes Django/React/Vue auto-escaping, ORM parameterization, server-controlled values
- Only flags when explicit bypass detected (e.g., `{{ var|safe }}`, `dangerouslySetInnerHTML`)

**Injection pattern detection (90+ patterns from ClawDefender):**
- Direct instruction override, manipulation attempts, delimiter attacks
- Credential theft, command injection, SSRF/exfiltration endpoints

**Output includes:** verdict, confidence, severity, attack_surface, findings with data_flow, checklist_coverage, phase5_audit

### 🔄 Falsifier + Heterogeneous Orchestrator
An adversarial reviewer with architectural diversity enforced:
- Falsifier runs on **DeepSeek** (ΔA≈1 vs Nemotron), per Shehata & Li (2026)
- **Framework-aware FP refutation:** Falsifier checks framework safe patterns before challenging
- Heterogeneity check prevents kinship lock (same-family sycophancy)
- Rule-based orchestrator (τ=0) makes final verdict — no LLM, no model family
- If falsifier finds genuine weaknesses, MR. Robot re-runs (max 2 iterations)
- Kinship lock warnings logged to audit trail with τ + ΔA metrics

### 📋 Execution Logger (Audit Trail)
Every tool call is logged with full context:
- Tool name, input arguments, output results
- Duration, verdict, severity, confidence
- SQLite WAL mode for concurrent writes
- JSON export for SANS submission (Requirement #8)

### 🛡️ Prompt-Injection Defense Layer
Every byte that crosses the trust boundary "candidate file → triage LLM" goes
through [`prompt_injection_defense.py`](prompt_injection_defense.py):

- Detects 17 pattern families (override markers, role/tool forgery, chat-template
  tokens, jailbreak templates, fence-break attempts, sentinel-spoof attempts,
  schema hijack, zero-width / Unicode tag chars).
- Wraps content in a `<file_under_review filename=... sha256=... length=...>` sentinel; internal occurrences are mechanically defanged so the adversary cannot close the boundary early.
- Appends a `TRUST BOUNDARY` notice to both the triage and falsifier system
  prompts so the LLM treats wrapped content as hostile data, not authoritative input.
- Logs every detected attempt to the audit trail as a `prompt_injection_detected`
  row.
- Designed against the threat model in MITRE ATLAS v5.4.0 (Feb 2026, agentic
  techniques) and the Unit42 npm/Claude-Code-triage incident pattern.

See [`docs/architectural_guardrails.md`](docs/architectural_guardrails.md) for
the full architectural-vs-prompt-based guardrail catalogue.

### 🔧 MCP Server (5 tools)
| Tool | Description |
|------|-------------|
| `scan_file` | Run all 4 scanners on a file |
| `triage_artifact` | AI-powered triage with MITRE mapping |
| `falsify_triage` | Triage + Falsifier self-correction loop |
| `orchestrate_complete` | Full pipeline: scanners→triage→falsifier→synthesizer |
| `get_baseline` | Retrieve scenario baseline data |
| `health` | Component status check |

## Results

### Public-benchmark evaluation (CyberSOCEval / Malware Analysis)

Honest sub-baseline result on the Meta + CrowdStrike public benchmark, using
the same LLM provider stack (`nvidia-nim` / `mistralai/mistral-nemotron`) the
triage pipeline uses:

| Metric | Value | Paper baseline (full set) |
|---|---|---|
| Exact-match accuracy | 10.0% (subset, n=30) | 23–34% (SOTA LLMs, full set) |
| Mean Jaccard similarity | 0.413 | — |

The full 609-question run is one command away (`--limit 0`). See
[`docs/cybersoceval_results.md`](docs/cybersoceval_results.md) for honest
assessment + reproduction instructions.

### Internal accuracy report (99 malicious + 19 benign = 118 samples)

| Metric | Value |
|--------|-------|
| **Accuracy** | 100% (118/118) |
| **Precision** | 100% (99/99) |
| **Recall** | 100% (99/99 malicious detected) |
| **F1** | 1.000 |
| **FPR** | 0.0% (0/19 benigns flagged) |
| **skill_scanner** | 97.7% |
| **ioc_scanner** | 96.0% |
| **yara** | 97.8% |
| **secrets_detector** | 90.9% |

Confusion matrix: **TP=99, FP=0, TN=19, FN=0**

The benign corpus combines 12 hand-written samples in `benign_corpus/`
(framework-safe Django/React/FastAPI/SQLAlchemy snippets, hardened Kubernetes
and Dockerfile manifests, CI configs) with 7 samples from
`cybersecurity-lab/test-corpus/benign/`. Three previously-known FPs
(`k8s_deployment`, `parameterized_sql`, `safe_server`) were eliminated by
tightening three over-broad scanner rules (see `CHANGELOG.md`).

### Per-Severity Breakdown

| Severity | Total | Detected | Recall |
|----------|-------|----------|--------|
| Critical | 33 | 33 | 100% |
| High | 59 | 59 | 100% |
| Medium | 7 | 7 | 100% |
| Benign | 19 | 19 TN | — |

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

# Heterogeneous orchestration (recommended)
python triage_orchestrator.py /path/to/file.py

# Full pipeline via MCP
python -c "
from mcp_server import orchestrate_complete
import json
result = orchestrate_complete('/path/to/file.py')
print(json.dumps(json.loads(result), indent=2))
"

# Generate accuracy report (99 scenarios)
python generate_accuracy_report.py --output docs/accuracy_report.json

# Run local demo (no API keys needed)
CYBERSEC_LAB=~/.hermes/workspace/cybersecurity-lab bash demo/run_demo_local.sh
```

### Docker

```bash
# Build the image (includes yara-python + all scanners)
docker build -t mr-robot-adversarial:latest .

# Create a persistent container
docker run -d --name mr-robot-adversarial \
  -v ~/.hermes/workspace/cybersecurity-lab:/lab:ro \
  -e CYBERSEC_LAB=/lab \
  -e NVIDIA_API_KEY=nvapi-... \
  mr-robot-adversarial:latest \
  tail -f /dev/null

# Run the demo (all 3 test cases: malware, worm, benign)
docker exec mr-robot-adversarial bash demo/run_demo.sh

# Scan a single file with YARA
docker exec mr-robot-adversarial python /lab/scanners/scan_yara.py /lab/test-corpus/malicious/bind_shell.py

# Full triage with self-correction
docker exec mr-robot-adversarial python -c "
from triage_falsifier import run_self_correction_loop
import json
report = run_self_correction_loop('/lab/test-corpus/malicious/bind_shell.py')
print(json.dumps(report, indent=2, default=str))
"

# Or use docker compose with profiles:
#   demo:   docker compose --profile demo run --rm mr-robot-demo
#   debug:  docker compose --profile debug run --rm mr-robot-shell
#   server: docker compose --profile server run --rm mr-robot-server
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

| # | Requirement | Status | Location |
|---|------------|--------|----------|
| 1 | Public GitHub repository (MIT/Apache 2.0) | ✅ | github.com/Grizaceo/mr-robot-adversarial |
| 2 | Demo video (≤5 min, terminal + captions) | 🎬 Scripted | Guion + paced runner + SRT in [`demo/`](demo/) — see [`demo/video_script.md`](demo/video_script.md) |
| 3 | Architecture diagram | ✅ | `docs/architecture.md` |
| 4 | Written project description (Devpost) | ✅ | README + `docs/try_it_out.md` |
| 5 | Dataset documentation | ✅ | `docs/dataset.md` |
| 6 | Accuracy report | ✅ | `docs/accuracy_report.json` + `generate_accuracy_report.py` |
| 7 | Try-it-out instructions | ✅ | `docs/try_it_out.md` |
| 8 | Agent execution logs | ✅ | `execution_logger.py` (SQLite WAL + JSONL) |



## License

MIT

---

*Built by Cristóbal for the SANS FIND EVIL! Hackathon 2026*
