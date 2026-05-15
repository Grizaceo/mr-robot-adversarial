# Changelog

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
