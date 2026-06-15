#!/usr/bin/env python3
"""Hunt for a REPRODUCIBLE self-correction (FALSIFIED -> verdict flip) on real LLM runs.

Runs the full orchestrator with the falsifier FORCED over a set of candidate files,
captures the per-iteration falsifier status and whether the final verdict differs from
the first-pass triage verdict (a genuine self-correction). Repeats each file to gauge
reproducibility. Prints a compact table; full JSON per run saved under /tmp.
"""
import json
import os
import sys
import time
from pathlib import Path

os.environ["MR_ROBOT_FORCE_FALSIFIER"] = "1"

from triage_orchestrator import orchestrate  # noqa: E402

CANDIDATES = [
    # benign-but-scanner-flagged -> natural MALICIOUS->BENIGN self-correction candidates
    "benign_corpus/typescript_dto.ts",       # the known 1 FP (AWS-key-shaped fixture)
    "benign_corpus/parameterized_sql.py",
    "benign_corpus/django_user_view.py",
    "benign_corpus/k8s_deployment.yaml",
    "benign_corpus/fastapi_orders.py",
    "benign_corpus/express_health.js",
    "benign_corpus/secure_dockerfile",
]
REPEATS = 2

rows = []
for path in CANDIDATES:
    if not Path(path).exists():
        print(f"SKIP (missing): {path}", flush=True)
        continue
    for r in range(REPEATS):
        t0 = time.time()
        try:
            rep = orchestrate(path)
        except Exception as e:
            print(f"ERROR {path} run{r}: {e}", flush=True)
            continue
        ch = rep.get("correction_history") or []
        statuses = [c.get("falsifier_status") for c in ch]
        first_iter = ch[0] if ch else {}
        final = rep.get("final_verdict")
        triage_v = (rep.get("triage_report") or {}).get("verdict")
        # a self-correction = falsifier FALSIFIED at least once AND final differs from initial triage
        falsified = any(s == "FALSIFIED" for s in statuses)
        meta = rep.get("_meta", {})
        rows.append({
            "file": path, "run": r, "final": final, "triage": triage_v,
            "falsifier_statuses": statuses, "falsified_once": falsified,
            "kinship": meta.get("kinship_lock_risk"),
            "propagator": meta.get("propagator_family"), "auditor": meta.get("auditor_family"),
            "secs": round(time.time() - t0, 1),
        })
        outp = f"/tmp/sc_{Path(path).stem}_r{r}.json"
        Path(outp).write_text(json.dumps(rep, indent=2, default=str))
        flag = "  <<< FALSIFIED" if falsified else ""
        print(f"{path:42s} run{r}  triage={triage_v}  final={final}  "
              f"fals={statuses}  ({rows[-1]['secs']}s){flag}", flush=True)

print("\n==== SELF-CORRECTION CANDIDATES (FALSIFIED at least once) ====", flush=True)
hits = [x for x in rows if x["falsified_once"]]
if hits:
    for x in hits:
        print(f"  {x['file']} run{x['run']}: triage={x['triage']} -> final={x['final']} "
              f"statuses={x['falsifier_statuses']}", flush=True)
else:
    print("  none — falsifier SURVIVED on every run (no real self-correction observed)", flush=True)
print(f"\nTotal runs: {len(rows)}; FALSIFIED-at-least-once: {len(hits)}", flush=True)
