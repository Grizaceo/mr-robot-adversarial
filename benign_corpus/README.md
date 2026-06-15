# Benign Corpus

A set of realistic, legitimate code samples used to measure the **false positive
rate** of the MR. Robot Adversarial pipeline.

Together with the benign files in `cybersecurity-lab/test-corpus/benign/`,
this contributes to the 38 benign samples balanced against 135 malicious
scenarios in the 173-sample benchmark.

## Why this exists

Without benigns, an "accuracy report" is just recall. A scanner that flags
*everything* would score 100% recall but be useless in production. Including
benigns lets us measure **precision** and **FPR** honestly.

## Selection criteria

Each file exercises one or more patterns that the MR. Robot system prompt and
Falsifier are designed to recognize as **safe**:

| File | Pattern exercised |
|---|---|
| `django_user_view.py` | ORM parameterization + auto-escaped templates |
| `react_search_box.jsx` | React `{var}` auto-escaping |
| `fastapi_orders.py` | Pydantic validation + SQLAlchemy ORM |
| `parameterized_sql.py` | psycopg2 `%s` bind parameters |
| `csv_aggregator.py` | Pure stdlib computation, no I/O beyond file |
| `fibonacci.py` | Pure computation |
| `express_health.js` | Health endpoint with no user-controlled SQL |
| `k8s_deployment.yaml` | Hardened pod spec (non-root, read-only FS, caps dropped) |
| `github_ci.yml` | Minimal CI with read-only permissions |
| `typescript_dto.ts` | DTO + zod schema validation |
| `secure_dockerfile` | Non-root user, multi-stage, minimal surface |
| `markdown_renderer.py` | HTML sanitization with allow-list (bleach) |

These are exactly the cases where a naive keyword scanner would false-positive
(words like `eval`, `exec`, `subprocess`, `query`, `password` appear in
legitimate code all the time).

## Generating the report

```bash
python generate_accuracy_report.py --output docs/accuracy_report.json
```

The generator scans both `benign_corpus/` (this directory) and
`$CYBERSEC_LAB/test-corpus/benign/` and reports TP, FP, TN, FN.
