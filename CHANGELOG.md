# Changelog

## 2026-05-15 — Public-benchmark evaluation (CyberSOCEval)

### Added
- **`evals/cybersoceval_malware.py`** — eval harness that runs the official
  CyberSOCEval Malware Analysis multiple-choice questions (609 total, joint
  Meta + CrowdStrike open-source benchmark) through the same LLM provider
  stack the triage pipeline uses, and reports exact-match accuracy plus
  Jaccard similarity. Pulls questions from PurpleLlama and sandbox reports
  from CyberSOCEval_data.
- **`docs/cybersoceval_results.md`** — honest writeup of the current result
  (10.0% exact-match, 0.413 Jaccard on a seeded n=30 subset). Below the
  paper's 23-34% baseline band; the report explains why (overselection on
  MCQ format) and how to reproduce.
- **`docs/cybersoceval_results.json`** — per-question outcomes for audit.

### Why
SANS rubric criterion #2 (`IR Accuracy`) is judged across submissions; a
self-built corpus is informative but not comparable. A public benchmark
makes the LLM-choice claim verifiable, even when the number is unflattering.

---

## 2026-05-15 — Prompt-injection defense + architectural guardrails

Driven by a SOTA grounding pass (Microsoft MDASH announcement of 12 May 2026,
Claude Mythos Preview, MITRE ATLAS v5.4.0, PromptArmor ICLR 2026).

### Added
- **`prompt_injection_defense.py`** — new trust-boundary layer between
  `validate_target_file` and the LLM. Detects 17 pattern families (system
  override, role/tool forgery, ChatML/Llama chat-template tokens,
  "ignore previous", DAN/dev-mode, fence-break, sentinel-spoof, schema
  hijack, base64 blobs, zero-width / Unicode tag chars). Wraps content in a
  `<file_under_review filename=… sha256=… length=…> … </file_under_review>`
  sentinel with mechanical defang of internal close tags so the adversary
  cannot break out.
- `TRUST_BOUNDARY_NOTICE` appended to both `SYSTEM_PROMPT` (triage) and
  `FALSIFIER_SYSTEM_PROMPT` (auditor). Tells the LLM the sentinel content
  is hostile data, that injection attempts are *evidence* (to flag with
  category `prompt_injection_attempt`), and that the 5-phase workflow is
  the only source of authority.
- `agents/mr_robot/triage.py:get_last_injection_scan` so callers (and the
  audit logger) can retrieve the scan result for any candidate.
- Audit-trail row `prompt_injection_detected` written for every
  attempted injection.
- **`tests/injection_corpus/`** — 7 curated injection fixtures: system
  override, role marker, ChatML chat-template, markdown fence-break,
  tool-call forgery, DAN-style jailbreak, sentinel spoof.
- **`tests/test_prompt_injection_defense.py`** — 26 tests: detector
  recall on the injection corpus (all 7 caught at CRITICAL/HIGH),
  precision on the benign corpus (no CRITICAL false positives),
  sentinel containment (spoofed sentinels are mechanically defanged),
  system-prompt integrity, and the `_build_prompt` audit hook.
- **`docs/architectural_guardrails.md`** — explicit catalogue of every
  guardrail tagged Architectural (9), Hybrid (3), or Prompt-based (5),
  with file:line references. Maps directly to SANS rubric criterion #4.

### Changed
- `agents/mr_robot/triage.py:_build_prompt` now wraps candidate content
  through `scan_and_wrap` before insertion into the prompt.
- `triage_falsifier.py:_build_falsification_prompt` same wrapping for
  the auditor side, so propagator and auditor share the trust boundary.
- README — added `🛡️ Prompt-Injection Defense Layer` section pointing
  at the new module and guardrails doc.

### Why this matters for the SANS rubric
SANS criterion #4 (`Constraint Implementation`) literally asks whether
guardrails are *architectural or prompt-based*. This release ports the
single biggest gap surfaced by the SOTA grounding pass into the
architectural side and documents it.

### Tests
- Test suite grew from 60 → 85 passing (+25 new injection-defense tests).
- All previous tests still green.

---

## 2026-05-15 — End-to-end review fixes

Driven by an internal end-to-end review of the repo ahead of the SANS FIND
EVIL! 2026 submission deadline.

### Added
- **`benign_corpus/`** — 12 hand-written benign code samples exercising the
  framework-safe patterns the triage prompt and Falsifier are supposed to
  recognize (Django ORM + auto-escaped templates, React `{var}` rendering,
  FastAPI + Pydantic, parameterized psycopg2, hardened Kubernetes pod spec,
  multi-stage non-root Dockerfile, allow-listed Markdown rendering, CI
  config with read-only permissions, pure-computation samples).
- **Benign control set in accuracy report.** `generate_accuracy_report.py`
  now scans `benign_corpus/` and `cybersecurity-lab/test-corpus/benign/`,
  treats them as ground-truth `BENIGN`, and reports real TN/FP. Output
  also lists each false positive with the offending scanner.
- **Supporting literature** for the Heterogeneity Mandate. Primary source
  remains Shehata & Li (2026, arXiv:2604.27274); now cross-referenced with
  Du et al. 2023 (multiagent debate, arXiv:2305.14325), Wang et al. 2022
  (self-consistency, arXiv:2203.11171), Liang et al. 2023 (divergent
  thinking, arXiv:2305.19118), and Sharma et al. 2023 (LLM sycophancy,
  arXiv:2310.13548) so a reviewer who is unfamiliar with the primary paper
  can still triangulate the claim.

### Changed
- `docs/accuracy_report.json` regenerated with full confusion matrix:
  **TP=99, FP=3, TN=16, FN=0** (Accuracy 97.5%, Precision 97.1%,
  Recall 100%, F1 0.985, FPR 15.8%). Replaces the prior
  positives-only report.
- `README.md` and `docs/dataset.md` updated to report the new metrics
  honestly, including the three known false positives.
- `BLUEPRINT.md` status updated to "READY FOR SUBMISSION (pending demo
  video)" with a pointer to this changelog.

### Fixed
- `agents/mr_robot/triage.py:52,71` — corrected stale `github.com/davi/...`
  HTTP-Referer URLs left over from the DAVI → MR. Robot rename. Now
  point at `github.com/Grizaceo/mr-robot-adversarial`.

### Known issues (deliberately not suppressed)
- Three benign samples produce false positives that should be addressed
  in future scanner-rule iterations rather than hidden:
  - `benign_corpus/k8s_deployment.yaml` — flagged by `ioc_scanner`.
  - `benign_corpus/parameterized_sql.py` — flagged by `skill_scanner`
    on the `%s` bind syntax.
  - `cybersecurity-lab/test-corpus/benign/safe_server.js` — flagged by
    `skill_scanner`.
- The "Per-Tag Breakdown" treats the synthetic `benign` tag as a recall
  bucket (0% by construction); cosmetic, not a metric defect.

### Not changed in this pass
- Demo video (still pending; declared in submission checklist).
- Orchestrator integration into the accuracy report. The report still uses
  scanners-only labelling (`MALICIOUS if any scanner flagged`); promoting
  the orchestrator into the report is the next planned step.
