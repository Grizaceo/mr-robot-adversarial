# CyberSOCEval — Malware Analysis (subset evaluation)

## What this is

A real evaluation on a real public benchmark.

The MR. Robot pipeline's primary accuracy report (`docs/accuracy_report.json`)
runs on a self-built corpus of 135 malicious scenarios + 38 benign samples (173 total).
That number is informative but **not comparable** to other hackathon
submissions because it is private to this project.

This file reports performance on **CyberSOCEval / Malware Analysis** — the
joint Meta + CrowdStrike open-source benchmark released alongside
CyberSecEval 4 — using the **same LLM provider stack** the triage pipeline
uses. Results here can be cross-referenced against the published baselines.

## What this is NOT

- It is **not the full 609-question** benchmark. The default run is a seeded
  random subset of 30 questions so the experiment fits in ~1 minute and a
  few API calls. The full 609-question run is available by passing
  `--limit 0`.
- It is **not the MR. Robot 5-phase triage prompt**. CyberSOCEval is
  multiple-choice over sandbox JSON; MR. Robot's prompt is engineered for
  source-code triage. The harness uses the same provider stack but a
  benchmark-appropriate MCQ prompt so we measure the LLM tier, not the
  prompt-engineering of an unrelated task.

## Run summary (current)

| Field | Value |
|---|---|
| Benchmark | CyberSOCEval / Malware Analysis (subset) |
| Provider | `nvidia-nim` (`mistralai/mistral-nemotron`) |
| Questions evaluated | 30 (of 609 in the full set) |
| Random seed | 42 |
| **Exact-match accuracy** | **10.0%** |
| **Mean Jaccard similarity** | **0.413** |
| Wall time | ~65 s |

### Per attack family

| Family | n | Exact-match | Mean Jaccard |
|---|---:|---:|---:|
| infostealers | 6 | 16.7% | 0.38 |
| killers | 8 | 0.0% | 0.42 |
| ransomware | 5 | 20.0% | 0.37 |
| remcos | 4 | 0.0% | 0.25 |
| um_unhooking | 7 | 14.3% | 0.56 |

### Baseline (CyberSOCEval paper, Deason et al. 2025)

The published baselines on the **full** malware-analysis benchmark are
**23–34% accuracy** across a panel of SOTA LLMs.

## Honest assessment

Our subset result (10%) is **below** the paper's baseline band. Two reasons
are visible in the verbose log:

1. **Overselection.** Nemotron tends to mark every option that could
   plausibly apply rather than only those *evidenced* by the sandbox report.
   CyberSOCEval penalizes overselection at the same weight as omission, so
   high recall on options translates to low exact-match. The Jaccard score
   (0.41) reflects this: partial-credit retrieval is reasonable, set
   equality is not.
2. **Subset variance.** 30 is small. With a binomial CI at p=0.10 the 95%
   interval is roughly **[2%, 27%]**. The point estimate is uncertain;
   the full 609-question run is needed for a tight number.

## Reproducing the run

```bash
# Once: pull the public data sources (MIT / CC-BY-SA).
git clone --depth 1 https://github.com/CrowdStrike/CyberSOCEval_data.git /tmp/CyberSOCEval_data
git clone --depth 1 https://github.com/meta-llama/PurpleLlama.git /tmp/PurpleLlama

# Subset (≈1 min, default 30 questions).
python evals/cybersoceval_malware.py \
    --questions /tmp/PurpleLlama/CybersecurityBenchmarks/datasets/crwd_meta/malware_analysis/questions.json \
    --sandbox-root /tmp/CyberSOCEval_data/data/hybrid-analysis \
    --provider nvidia-nim \
    --output docs/cybersoceval_results.json --verbose

# Full run (≈30 min, ~609 API calls).
python evals/cybersoceval_malware.py --limit 0 …
```

The harness writes per-question outcomes to `docs/cybersoceval_results.json`
for audit.

## Why we include this in the submission

The SANS FIND EVIL! rubric weights `IR Accuracy` as one of six equal
criteria and asks judges to compare submissions on accuracy. A self-built
test set can show that the **pipeline works**; only a public benchmark can
show **how good the LLM choice actually is**.

By reporting an honest sub-baseline result we:

1. Demonstrate the LLM-comparison is real (we did run it).
2. Surface a concrete area for improvement (overselection on MCQ format).
3. Avoid the credibility cost of claiming numbers that are not externally
   verifiable.

## Data licensing

- Questions: CC-BY-SA-4.0 (Meta / CrowdStrike, see
  [`CITATION.md`](https://github.com/CrowdStrike/CyberSOCEval_data/blob/main/CITATION.md)).
- Sandbox reports: each `LICENSE.md` under
  `CyberSOCEval_data/data/hybrid-analysis/<category>/`.
- Code in `evals/cybersoceval_malware.py`: MIT, same as this repo.

## Citation

If you use this harness or these numbers, cite the upstream paper:

```
@misc{deason2025cybersoceval,
  title  = {CyberSOCEval: Benchmarking LLMs Capabilities for Malware
            Analysis and Threat Intelligence Reasoning},
  author = {Deason, L. and Bali, A. and Bejean, C. and Bolocan, D. and
            Crnkovich, J. and Croitoru, I. and Durai, K. and Midler, C. and
            Miron, C. and Molnar, D. and Moon, B. and Ostarcevic, B. and
            Peltea, A. and Rosenberg, M. and Sandu, C. and Saputkin, A. and
            Shah, S. and Stan, D. and Szocs, E. and Wan, S. and Whitman, S. and
            Krasser, S. and Saxe, J.},
  year   = {2025},
  url    = {https://arxiv.org/abs/2509.20166}
}
```
