# Heterogeneity Validation — DeepSeek vs Nemotron Comparative Eval

## Purpose

The heterogeneity mandate (Shehata & Li 2026, arXiv:2604.27274) predicts that
using **architecturally distinct** models as propagator and auditor reduces
error correlation and prevents Logic Saturation.  This document describes how
to **empirically validate** that claim using the CyberSOCEval malware-analysis
benchmark, and provides the harness and expected-result schema.

The run itself requires OpenRouter (DeepSeek) budget and is therefore
**not executed for the NVIDIA-NIM-only hackathon submission**.  The harness is
complete; replicate by following the command below.

---

## Hypothesis

If Shehata & Li (2026) is correct, then:

1. Nemotron and DeepSeek make **non-correlated errors** on CyberSOCEval MCQs.
2. A combined vote (propagator + auditor) outperforms either model alone.
3. When the two models agree, accuracy is **higher** than when they disagree.

Formally: if *ε_N* = Nemotron error set and *ε_D* = DeepSeek error set, then

    Jaccard(ε_N, ε_D) < 0.3     ← architectural independence
    |ε_N ∩ ε_D| / |ε_N ∪ ε_D|  ← overlap ratio

An overlap ratio above 0.6 would indicate kinship-lock risk for this task class.

---

## How to Run

```bash
# Prerequisites
export NVIDIA_API_KEY=nvapi-...         # for Nemotron
export OPENROUTER_API_KEY=sk-or-...     # for DeepSeek

# Clone public data (once)
git clone --depth 1 https://github.com/CrowdStrike/CyberSOCEval_data.git /tmp/CyberSOCEval_data
git clone --depth 1 https://github.com/meta-llama/PurpleLlama.git /tmp/PurpleLlama

# Run Nemotron on 100-question subset
python evals/cybersoceval_malware.py \
    --questions /tmp/PurpleLlama/CybersecurityBenchmarks/datasets/crwd_meta/malware_analysis/questions.json \
    --sandbox-root /tmp/CyberSOCEval_data/data/hybrid-analysis \
    --provider nvidia-nim \
    --limit 100 --seed 42 \
    --output docs/hetero_nemotron.json --verbose

# Run DeepSeek on the SAME 100 questions (same seed)
python evals/cybersoceval_malware.py \
    --questions /tmp/PurpleLlama/.../questions.json \
    --sandbox-root /tmp/CyberSOCEval_data/data/hybrid-analysis \
    --provider openrouter \
    --limit 100 --seed 42 \
    --output docs/hetero_deepseek.json --verbose

# Compute correlation stats
python - <<'EOF'
import json
from pathlib import Path

n = json.loads(Path("docs/hetero_nemotron.json").read_text())["results"]
d = json.loads(Path("docs/hetero_deepseek.json").read_text())["results"]

errors_n = {r["sha256"] for r in n if not r["exact_match"]}
errors_d = {r["sha256"] for r in d if not r["exact_match"]}

union = errors_n | errors_d
intersection = errors_n & errors_d
jaccard = len(intersection) / len(union) if union else 0.0

print(f"Nemotron errors: {len(errors_n)}/100  ({100-len(errors_n)}% exact-match)")
print(f"DeepSeek errors: {len(errors_d)}/100  ({100-len(errors_d)}% exact-match)")
print(f"Shared errors:   {len(intersection)}")
print(f"Jaccard(ε_N, ε_D): {jaccard:.3f}  (< 0.3 supports heterogeneity mandate)")

# Simple majority vote
from collections import defaultdict
votes: dict[str, dict] = defaultdict(dict)
for r in n: votes[r["sha256"]]["n"] = set(r["predicted"])
for r in d: votes[r["sha256"]]["d"] = set(r["predicted"])
correct_map = {r["sha256"]: set(r["correct"]) for r in n}

vote_exact = 0
for sha, v in votes.items():
    combined = v.get("n", set()) | v.get("d", set())
    if combined == correct_map.get(sha, set()):
        vote_exact += 1
print(f"Union-vote exact-match: {vote_exact}/{len(votes)} ({vote_exact/len(votes):.1%})")
EOF
```

---

## Expected Results (design-time prediction)

Based on the theory and the n=30 subset results:

| Metric | Nemotron (alone) | DeepSeek (alone) | Union vote |
|---|---|---|---|
| Exact-match (est.) | ~10–15% | ~10–18% | ~15–22% |
| Mean Jaccard | ~0.41 | ~0.43 | ~0.48 |
| Error Jaccard (ε_N vs ε_D) | — | — | **< 0.3 expected** |

If error Jaccard is **above 0.5**, the models are kinship-locked for this task
and the heterogeneity mandate provides no benefit here.  In that case the
propagator/auditor pair should be re-evaluated for the source-code triage domain
(where the current system is deployed) rather than the CyberSOCEval MCQ domain.

---

## Relationship to the Pipeline

The CyberSOCEval eval uses a **benchmark-appropriate MCQ prompt**, not the
5-phase MR. Robot triage prompt.  The heterogeneity benefit is primarily claimed
for the source-code triage domain (where Nemotron = propagator, DeepSeek =
falsifier/auditor).  The CyberSOCEval eval is a **proxy** that tests model
diversity on a related cybersecurity task; a more direct validation would run
both models through the full triage pipeline on the same 99-scenario corpus
and compare finding sets.

---

## References

- Shehata & Li (2026), arXiv:2604.27274 — primary: Inverse-Wisdom Law, error
  correlation in homogeneous agent swarms.
- Du et al. (2023), arXiv:2305.14325 — multi-agent debate improves reasoning.
- Wang et al. (2022), arXiv:2203.11171 — self-consistency via diverse sampling.
- Krogh & Vedelsby (1995) — ensemble diversity ↔ error reduction.
- Dietterich (2000) — systematic review of ensemble methods.
