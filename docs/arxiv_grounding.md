# Academic & Source Grounding — MR. Robot Adversarial

**Scope:** SANS FIND EVIL! 2026
**References:** ArXiv + public frameworks (MITRE ATT&CK, NIST SP 800-61r3, OWASP LLM Top 10)
**Goal:** Map every layer of the system against peer-reviewed literature / established sources to assess soundness, originality, and gaps before submission. This document is a citation ledger a judge can scan and verify link by link.

---

## 1. Paper Map in the Code

The authors already left live citations in the source code. This document validates, complements, and uses them as the backbone of the evaluation.

| ID | Authors | Title (inferred) | Year | Where it appears |
|---|---|---|---|---|
| arXiv:2604.27274 | Shehata & Li | The Inverse-Wisdom Law: Architectural Tribalism and the Consensus Paradox in Agentic Swarms | 2026 | `README.md`, `triage_orchestrator.py`, `triage_falsifier.py`, `docs/heterogeneity_mandate.md`, `docs/heterogeneity_validation.md`, `docs/architectural_guardrails.md` |
| arXiv:2509.20166 | Deason et al. | CyberSOCEval: Benchmarking LLM Capabilities for Malware Analysis and Threat Intelligence Reasoning | 2025 | `docs/cybersoceval_results.md` (formal BibTeX citation) |
| arXiv:2305.14325 | Du et al. | Improving Factuality and Reasoning in Language Models through Multiagent Debate | 2023 | `triage_orchestrator.py`, `triage_falsifier.py`, `docs/heterogeneity_mandate.md` |
| arXiv:2203.11171 | Wang et al. | Self-Consistency Improves Chain of Thought Reasoning in Language Models | 2022 | `triage_orchestrator.py`, `docs/heterogeneity_mandate.md` |
| arXiv:2305.19118 | Liang et al. | Encouraging Divergent Thinking in Large Language Models through Multi-Agent Debate | 2023 | `triage_orchestrator.py`, `docs/heterogeneity_mandate.md` |
| arXiv:2310.13548 | Sharma et al. | Towards Understanding Sycophancy in Language Models | 2023 | `triage_orchestrator.py`, `triage_falsifier.py`, `docs/heterogeneity_mandate.md` |

**Note:** The project cites these references in the source code (not only in the README). That is a sound practice: a reviewer can trace a design decision back to a specific paper.

**Caveat on the lead citation:** arXiv:2604.27274 (Shehata & Li) is a recent preprint. The repo's claims about it should be read as "novelty reinforced by established prior work" — the multi-agent debate, self-consistency, and sycophancy results (Du, Wang, Liang, Sharma) stand on their own and carry the architectural argument even if the single preprint's exact formulas are not yet independently reproduced. Before final submission, confirm the exact formulas (`μ=σ(1−B)+τB`) and theorem numbering directly against the preprint PDF.

---

## 2. Grounding by System Layer

### 2.1 Scanners — Precision and Coverage

**Base papers:**
- arXiv:2509.20166 (Deason et al.) — The benchmark uses sandbox JSON (Hybrid Analysis), which positions the scanners as a *pre-screening* layer against forensic ground truth.
- SANS context: most competitors run only static scanners (YARA, sigma).

**Assessment:**
- 4 parallel scanners (skill, IOC, YARA, secrets) is defensible as a minimal "defense-in-depth" layer.
- 100% accuracy on the private corpus (99 TP / 19 TN) with no FPR is suspiciously clean; it should be reported with the explicit warning that the corpus is private and self-curated.

### 2.2 MR. Robot Triage — LLM + Structure

**Base papers:**
- arXiv:2604.27274 (Shehata & Li) — Inverse-Wisdom Law, Heterogeneity Mandate.
- arXiv:2305.14325 (Du et al.) — Multi-agent debate improves factuality.
- arXiv:2203.11171 (Wang et al.) — Self-consistency via diverse reasoning paths.

**Mapping to the design:**

| Component | Paper grounding | Function |
|---|---|---|
| MR. Robot (propagator) | — | Generates initial triage |
| Falsifier (DeepSeek/Nemotron alternate) | arXiv:2305.14325, 2305.19118 | Heterogeneous auditor |
| Heterogeneity check (ΔA≈1) | arXiv:2604.27274 | Prevents kinship lock / Logic Saturation |
| 5-phase prompt | — | Cognitive structure compatible with incident response |

**Assessment:**
- The propagator/auditor split using architecturally distinct models (Nemotron vs DeepSeek) is an original contribution relative to a hackathon where most entrants use a single LLM.
- The prompt with MITRE ATT&CK IDs and a 12-key checklist standardizes the output, reducing model variability (partially derivable from arXiv:2203.11171).

### 2.3 Falsifier — Adversarial Verification

**Base papers:**
- arXiv:2305.14325 (Du et al.) — Multi-agent debate improves factual reasoning.
- arXiv:2310.13548 (Sharma et al.) — Same-family reviewers tend to confirm (sycophancy) rather than challenge.

**Valid design:**
- Threshold ΔA≈1 (models from distinct families).
- Max 2 iterations to avoid infinite loops.

**Gap:**
- There is no published empirical validation of this loop. The Falsifier exists in code, but the error variance between Nemotron and DeepSeek over CyberSOCEval is not quantified in this repo.

### 2.4 Cross-Stack Correlator — Event Correlation

**Base papers:**
- arXiv:2604.27274 (Shehata & Li) — Heterogeneous systems detect patterns that single-family agents miss (multi-layer detection is a natural implication of the Cascade Point Theorem, although not cited explicitly).

**Current implementation:**
- SQLite query over `audit_trail.db`.
- Threshold of 3 events in 24h with the same `tool_name`.

**Grounding:**
- Simple correlation is the minimum viable signal for a SIEM (see NIST SP 800-61r3, "Analysis" section).
- The "same tool_name in 24h" rule is weak: real campaigns use multiple tools (YARA + IOC + memory). Could be upgraded to an IOC co-occurrence graph.

### 2.5 Episodic Memory / Few-Shot Retrieval (Improvement 1)

**Base papers:**
- arXiv:2604.27274 (Shehata & Li) — The Inverse-Wisdom Law suggests that well-retrieved prior examples mitigate novice error.
- Lewis et al. (2020) — RAG. This component is RAG over past executions.

**Status:**
Schema is ready, code not yet integrated. Without this component, the "self-improving agents" claim is not empirically defensible.

---

## 3. External Evaluation: CyberSOCEval

**Reference:** arXiv:2509.20166 (Deason et al., 2025)

| Metric | Paper value | Our value (pre-fix) | Gap |
|---|---|---|---|
| Exact-match (multi-select MCQ) | 23–34% | 10.0% | -13 to -24 pts |
| Subset variance | n=609 | n=30, CI [2%, 27%] | High uncertainty |
| Models evaluated in paper | Various SOTA LLMs | Only Nemotron (NVIDIA NIM) | Missing multi-model comparison |

**Grounded interpretation:**
The 10% is not an absolute failure: the scheme penalizes overselection, and the Nemotron model tends to over-select (documented in `docs/cybersoceval_results.md` as the primary cause). It is a reward-alignment problem, not a pipeline-capability problem. The applied fix (strict prompt + improved `parse_answer`) should raise the number when the gate is re-run.

**Future work:**
- Run the full run (n=609) to reduce variance.
- Report a per-attack-family breakdown as the paper does (ransomware, infostealer, etc.).

---

## 4. FIND EVIL! Criteria — Rubric Alignment (Grounded Self-Assessment)

### Completion & On-Time
- ✅ Public repo (`github.com/Grizaceo/mr-robot-adversarial`).
- ✅ Installable code (`pip install -r requirements.txt`).
- ⚠️ No video yet (day 30; deadline June 15).
- ✅ Tests green (129 passed, 3 skipped).

### Self-Improving Agents
- ✅ `accuracy_report.json` + public benchmark report.
- ❌ Retrieval store not integrated (only new columns).
- ⚠️ Falsifier exists but without published multi-model validation.

### Real-World Impact
- ✅ MTTR claims: 12s vs hours of manual work (E2E report).
- ⚠️ Concrete actions (quarantine, block IP) not shown in public output.
- ✅ SIFT bridge functional (though deferred from full VM).

### Demo Clarity (excluding video)
- ✅ `docs/e2e_test_results.md` shows real output.
- ⚠️ A sharper "before/after" is missing in the README for judges who skim quickly.

---

## 5. Formal References to Cite in the Repo

**Add to a README "Academic Foundation" block:**

```
[1] Shehata, D. & Li, M. (2026). The Inverse-Wisdom Law: Architectural
    Tribalism and the Consensus Paradox in Agentic Swarms.
    arXiv:2604.27274. University of Waterloo.

[2] Deason, L. et al. (2025). CyberSOCEval: Benchmarking LLM Capabilities
    for Malware Analysis and Threat Intelligence Reasoning.
    arXiv:2509.20166. Meta / CrowdStrike.

[3] Du, Y. et al. (2023). Improving Factuality and Reasoning through
    Multiagent Debate. arXiv:2305.14325.

[4] Wang, X. et al. (2022). Self-Consistency Improves Chain of Thought
    Reasoning. arXiv:2203.11171.

[5] Liang, T. et al. (2023). Encouraging Divergent Thinking in Large
    Language Models through Multi-Agent Debate. arXiv:2305.19118.

[6] Sharma, V. et al. (2023). Towards Understanding Sycophancy in Language
    Models. arXiv:2310.13548.

[7] MITRE ATT&CK Framework. https://attack.mitre.org/

[8] NIST SP 800-61r3. Computer Security Incident Handling Guide.
    https://csrc.nist.gov/publications/detail/sp/800-61r3/final

[9] OWASP Top 10 for LLM Applications (2025).
    https://owasp.org/www-project-top-10-for-large-language-model-applications/
```

---

## 6. Error Codes and Risks (Mapped to Papers)

| Symptom in the repo | Grounded cause in the literature |
|---|---|
| Overselection in MCQ (10% exact-match) | arXiv:2310.13548 — same model as propagator and auditor → sycophancy / overconfident multi-select |
| High run-to-run variability | arXiv:2203.11171 — absence of self-consistency sampling |
| No use of prior retrieval | No RAG → repeats novice errors (arXiv:2604.27274, Inverse-Wisdom Law) |
| Weak correlator | arXiv:2604.27274 implies multivariate correlation reduces error; a single dimension (tool_name) is insufficient |

---

## 7. Suggested Next Steps (Concrete Actions)

1. **Commit this document** at `docs/arxiv_grounding.md`.
2. **Run the post-fix CyberSOCEval gate** (download datasets) to obtain an updated number that can be paraphrased against Deason et al.
3. **Implement the retrieval store** (TF-IDF + `build_few_shot_block`) to close the "self-improving agents" gap with explicit theoretical backing.
4. In the README, add an "Academic Foundation" block with the nine formal references above.
5. **Before submission**, open the Shehata & Li preprint (arXiv:2604.27274) and confirm the exact formulas and theorem numbering match what the repo cites — the single point not independently verified during this audit.
