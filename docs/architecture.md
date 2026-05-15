# Architecture Diagram — MR. Robot Adversarial

## System Architecture

```mermaid
graph TB
    subgraph Input["📁 Input"]
        FILE[Candidate File<br/>Python/JS/YAML/Shell]
    end

    subgraph Scanners["🔍 Scanner Suite (τ=0, deterministic)"]
        SS[skill_scanner<br/>44 rules: YARA-like + AST<br/>+ prompt injection<br/>+ ClawDefender patterns]
        IS[ioc_scanner<br/>12 URLs + 6 domains<br/>+ 10 heuristics]
        YR[scan_yara<br/>22KB custom rules<br/>C2 + backdoor primitives]
        SD[secrets_detector<br/>API keys + tokens<br/>+ credentials]
    end

    subgraph AI["🤖 AI Pipeline (heterogeneous)"]
        MR[MR. Robot<br/>Nemotron propagator<br/>5-phase review<br/>confidence levels<br/>framework-aware FP reduction]
        FALS[Falsifier<br/>DeepSeek auditor<br/>ΔA≈1 vs Nemotron<br/>framework-safe-pattern<br/>refutation]
        SYN[Orchestrator<br/>Rule-based synthesizer<br/>τ=0, non-LLM<br/>deterministic verdict]
    end

    subgraph Audit["📋 Audit Trail"]
        LOG[Execution Logger<br/>SQLite WAL mode<br/>12 fields per decision<br/>τ + ΔA metrics]
        JSONL[audit_trail.jsonl<br/>SANS requirement #8]
    end

    subgraph Output["📊 Output"]
        VERDICT[Final Verdict<br/>MALICIOUS/SUSPICIOUS<br/>/BENIGN/INCONCLUSIVE]
        REPORT[Structured Report<br/>confidence + severity<br/>MITRE ATT&CK mapping<br/>recommended actions]
    end

    FILE --> Scanners
    Scanners --> MR
    MR -->|confidence ≥ 0.90<br/>+ scanner agreement| SYN
    MR -->|confidence < 0.90<br/>or disagreement| FALS
    FALS -->|SURVIVED| SYN
    FALS -->|FALSIFIED<br/>max 2 iterations| MR
    SYN --> VERDICT
    SYN --> REPORT
    MR --> LOG
    FALS --> LOG
    LOG --> JSONL
    VERDICT --> Output
    REPORT --> Output

    style Input fill:#1a1a2e,stroke:#16213e,color:#e94560
    style Scanners fill:#0f3460,stroke:#16213e,color:#e94560
    style AI fill:#533483,stroke:#16213e,color:#e94560
    style Audit fill:#1a1a2e,stroke:#16213e,color:#e94560
    style Output fill:#16213e,stroke:#0f3460,color:#e94560
```

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│ TRUST BOUNDARY 1: Input Validation                              │
│ • validate_target_file() rejects paths outside allowed roots    │
│ • Binary files flagged (MAL-008)                                │
│ • File size limit (50KB default)                                │
├─────────────────────────────────────────────────────────────────┤
│ TRUST BOUNDARY 2: Scanner Suite (deterministic, τ=0)           │
│ • No LLM calls — pure regex + AST + YARA                       │
│ • No network access from scanners                               │
│ • Read-only file access                                         │
├─────────────────────────────────────────────────────────────────┤
│ TRUST BOUNDARY 3: AI Pipeline (heterogeneous)                   │
│ • MR. Robot (Nemotron) — propagator only                       │
│ • Falsifier (DeepSeek) — auditor only, ΔA≈1 enforced           │
│ • Orchestrator (rule-based) — τ=0, no LLM                      │
│ • Max 2 correction iterations (Shehata & Li 2026)               │
├─────────────────────────────────────────────────────────────────┤
│ TRUST BOUNDARY 4: MCP Server (architectural guardrails)         │
│ • Only safe functions exposed (scan, triage, falsify)           │
│ • No destructive commands (rm, chmod, exec)                     │
│ • No network access from MCP tools                              │
│ • All inputs validated before processing                        │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow

```
File Input
    │
    ▼
┌──────────────────┐
│ Input Validation │ ← Trust Boundary 1
│ (path, size,     │
│  binary check)   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Scanner Suite    │ ← Trust Boundary 2
│ (4 scanners,     │
│  deterministic)  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐     ┌──────────────────┐
│ MR. Robot        │────→│ Falsifier        │ ← Trust Boundary 3
│ (Nemotron)       │     │ (DeepSeek, ΔA≈1) │
│ 5-phase review   │←────│ max 2 iterations │
└────────┬─────────┘     └──────────────────┘
         │
         ▼
┌──────────────────┐
│ Orchestrator     │ ← Trust Boundary 3
│ (rule-based, τ=0)│
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Final Verdict    │
│ + Audit Trail    │ ← Trust Boundary 4
└──────────────────┘
```

## Heterogeneity Mandate (Shehata & Li 2026)

Per arXiv:2604.27274, same-family agent swarms produce kinship lock (τ≈1) → Logic Saturation → 100% error.

Our enforcement:
- **Propagator:** NVIDIA Nemotron (mistralai/mistral-nemotron)
- **Auditor:** DeepSeek (deepseek/deepseek-chat-v3-0324)
- **Synthesizer:** Rule-based (τ=0, no model family)
- **ΔA ≈ 1.0** (architecturally different families)
- **Max 2 iterations** (paper proves >2 with same family makes error worse)
