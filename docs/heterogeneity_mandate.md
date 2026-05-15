# Heterogeneity Mandate — Architectural Safety for MR. Robot Adversarial

> *"The synthesizer node must be heterogeneous — architectural diversity
> at the decision point is a formal safety requirement."*
> — **Shehata & Li (2026)**, Corollary 1

## Source

**Shehata, D. & Li, M. (2026).** "The Inverse-Wisdom Law: Architectural
Tribalism and the Consensus Paradox in Agentic Swarms."

- arXiv: [2604.27274](https://arxiv.org/abs/2604.27274)
- University of Waterloo
- 12,804 trajectories, 36 experiments, 3 SOTA models
- 7 primary contributions including formal proofs

## The Problem (Kinship Lock)

In a 3-agent swarm (propagator → auditor → synthesizer), when all agents
come from the **same model family**, a phenomenon called "kinship lock" emerges:

```
μ = σ(1 − B) + τB          (Synthesizer Gating Theorem)
```

Where:
- **μ** = terminal error probability
- **σ** = sycophantic weight (agreement with error because majority agrees)
- **τ** = tribalism coefficient (rejection of valid correction from "stranger")
- **B** = auditor accuracy

When τ→1 (same-family agents), **μ→τ≈1 regardless of B** — even a perfect
auditor (B=1) cannot prevent cascading errors. The agents reach a state
called **Logic Saturation**: internal disagreement = 0, factual error = 1.

### The Inverse-Wisdom Law (Theorem 3)

> In kinship-dominant swarms, adding more agents *increases* the stability
> of erroneous trajectories rather than the probability of truth.

The recurrence:
```
μ_{n+1} = Λ [μ_n·τ + (1−μ_n)·σ]
```

Under saturation (Λ→2, τ+σ≈1): μ_n → 1.0 as n → ∞.

## Our Vulnerability (Before Fix)

```
MR. Robot (Nemotron) → Falsifier (Nemotron) → Final Verdict
     propagator            auditor                synthesizer

ALL NVIDIA NEMOTRON FAMILY
→ τ high, σ high
→ κ = "HIGH" (kinship lock risk)
→ ΔA ≈ 0 (architectural distance)
```

When our demo showed `"falsifier_status": "SURVIVED"`, we had **no way to
distinguish** between:
1. The triage actually being correct, and
2. The falsifier being sycophantic (same-family agreement)

## The Fix (Heterogeneity Mandate)

Applied **Corollary 1** from the paper:

```
MR. Robot (Nemotron) → Falsifier (DeepSeek) → Orchestrator (rule-based)
     propagator            auditor (ΔA≈1)        synthesizer (τ=0)
```

| Component | Model Family | τ | Role |
|---|---|---|---|
| MR. Robot | Nemotron | — | Propagator: initial triage |
| Falsifier | **DeepSeek** | τ low | Auditor: ΔA≈1 vs Nemotron |
| Orchestrator | **Non-LLM** | **τ=0** | Synthesizer: deterministic rules |

### Why DeepSeek?

DeepSeek is architecturally far from Nemotron:
- Different training data distribution
- Different architecture (MLA vs standard attention)
- Different optimization target
- **ΔA ≈ 1** (maximum architectural distance)

Fallback chain for falsifier: `deepseek-chat-v3` → `deepseek-r1` → `qwen3-32b`
(All architecturally distant from Nemotron).

### Why Rule-Based Orchestrator?

A non-LLM synthesizer has **τ=0 by definition** — it has no model family to
be tribal about. It applies deterministic rules:
- If scanner + triage agree at >0.90 → direct verdict
- If falsifier SURVIVED with heterogeneous auditor → accept
- If falsifier FALSIFIED → re-run triage (max 2 iterations)
- If still disputed → flag for human review

The recurrence μ_{n+1} stabilizes at μ ≪ 1 because the heterogeneous auditor
prevents the Λ amplification.

## Validation

The orchestrator detects kinship lock at runtime and logs warnings:

```
[WARNING] SAME-FAMILY FALSIFICATION: per Shehata & Li (2026), this may be
           sycophantic agreement. Falsifier and Triage share Nemotron family
           (ΔA≈0, τ high).
```

## Primary Reference

- **Shehata, D. & Li, M. (2026).** *The Inverse-Wisdom Law: Architectural
  Tribalism and the Consensus Paradox in Agentic Swarms.* University of
  Waterloo. [arXiv:2604.27274](https://arxiv.org/abs/2604.27274).
- 7 theorems proven: Synthesizer Gating, Inverse-Wisdom Law, Sycophantic State
  Transition, Architectural Tribalism Asymmetry, Heterogeneity Mandate,
  Cascade Point, Logic Saturation.

## Supporting Literature

The Heterogeneity Mandate is consistent with — and reinforced by — earlier
work on multi-agent diversity and LLM sycophancy:

- **Du et al. (2023).** *Improving Factuality and Reasoning in Language
  Models through Multiagent Debate.* [arXiv:2305.14325](https://arxiv.org/abs/2305.14325).
  Multi-agent debate improves factuality; gains scale with model diversity.
- **Wang et al. (2022).** *Self-Consistency Improves Chain of Thought
  Reasoning in Language Models.* [arXiv:2203.11171](https://arxiv.org/abs/2203.11171).
  Aggregating diverse reasoning paths beats single-pass decoding.
- **Liang et al. (2023).** *Encouraging Divergent Thinking in Large Language
  Models through Multi-Agent Debate.* [arXiv:2305.19118](https://arxiv.org/abs/2305.19118).
  "Degenerate of thought" (early convergence on shared mistakes) is mitigated
  by forcing divergence — directly compatible with the kinship-lock framing.
- **Sharma et al. (2023).** *Towards Understanding Sycophancy in Language
  Models.* [arXiv:2310.13548](https://arxiv.org/abs/2310.13548). Empirical
  evidence that same-distribution reviewers tend to confirm rather than
  challenge — the σ term in the Synthesizer Gating Theorem.
- Krogh & Vedelsby (1995); Dietterich (2000) — classical ensemble theory:
  ensemble error decreases with **base learner diversity**, not just count.

Shehata & Li formalize for agentic swarms what this literature establishes
empirically and statistically for ensembles and multi-agent debate.

---

*Applied in: `triage_orchestrator.py` v1.0.0*
*Date: 2026-05-15*
