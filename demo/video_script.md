# Demo Video Script — MR. Robot Adversarial

**Target:** ≤ 5:00 (SANS requirement #2)
**Style:** Terminal-only, English on-screen captions, no voiceover
**Recording:** OBS Studio screen capture
**Driver:** `demo/run_video_demo.sh` (paces each step automatically)

The script below maps **1 scene = 1 clear screen + 1 caption + 1 command(s)**.
Captions go in OBS as a text source toggled per scene, OR added in post.

---

## Scene 1 — Title card  (0:00 – 0:08, 8s)

**Caption (centered, large):**
```
MR. Robot Adversarial
SANS FIND EVIL! Hackathon 2026
Autonomous AI Cyber Defense
```

**Terminal:** clear screen, optional `figlet` banner:
```bash
figlet -f slant "MR. Robot"
echo "Autonomous AI Cyber Defense  —  SANS FIND EVIL! 2026"
```

---

## Scene 2 — The problem  (0:08 – 0:25, 17s)

**Caption (top of screen, line by line as terminal scrolls):**
```
> An AI-driven adversary can breach in under 8 minutes.
> A human analyst still alt-tabs between tools.
> We close that gap: scanner → AI triage → adversarial review → verdict, in ~30s.
```

**Terminal:** plain `cat` of a short problem statement file, no commands beyond that.

---

## Scene 3 — Architecture in one screen  (0:25 – 0:50, 25s)

**Caption (top):**
```
Three trust layers, two model families, one rule-based judge.
```

**Terminal:**
```bash
sed -n '20,68p' README.md
```
(Prints the ASCII architecture block from README without showing the full file.)

---

## Scene 4 — Health check  (0:50 – 1:05, 15s)

**Caption:**
```
Health check — providers, scanners, audit DB.
```

**Terminal:**
```bash
python agents/mr_robot/triage.py --health
```

---

## Scene 5 — Malicious sample (bind shell)  (1:05 – 2:00, 55s)

**Caption A (first 5s):**
```
Sample 1: a Python bind shell. We expect MALICIOUS.
```

**Terminal:**
```bash
head -20 "$CYBERSEC_LAB/test-corpus/malicious/bind_shell.py"
```

**Caption B (next ~40s, swap as commands run):**
```
Step 1/3 — deterministic scanners (skill / IOC / YARA / secrets)
Step 2/3 — MR. Robot triage (gpt-oss-120b, 5-phase review)
Step 3/3 — Falsifier (Nemotron-3-Ultra) audits the triage
```

**Terminal:**
```bash
MR_ROBOT_FORCE_FALSIFIER=1 python triage_orchestrator.py \
  "$CYBERSEC_LAB/test-corpus/malicious/bind_shell.py" \
  --provider falsifier 2>/dev/null | jq '{
    verdict: .final_verdict,
    rationale,
    propagator: ._meta.propagator_family,
    auditor: ._meta.auditor_family,
    kinship_lock_risk: ._meta.kinship_lock_risk
  }'
```

**Caption C (final ~10s, on the verdict):**
```
Verdict: MALICIOUS
Propagator: gpt-oss   Auditor: nemotron   ΔA = 1.0  (heterogeneous)
```

---

## Scene 6 — Benign sample (the false-positive trap)  (2:00 – 2:45, 45s)

**Caption A:**
```
Sample 2: a Django view with parameterized ORM. Should be BENIGN.
```

**Terminal:**
```bash
cat benign_corpus/django_user_view.py
```

**Caption B:**
```
Framework-aware: the Falsifier knows Django auto-escapes templates
and that the ORM parameterizes filter() — no SQL injection vector.
```

**Terminal:**
```bash
python triage_orchestrator.py benign_corpus/django_user_view.py 2>/dev/null \
  | jq '{verdict: .final_verdict, rationale}'
```

**Caption C:**
```
Verdict: BENIGN — without the Falsifier this would have been a false alarm.
```

---

## Scene 7 — Adversarial review loop  (2:45 – 3:40, 55s)

**Caption A:**
```
Sample 3: the Python bind shell again — this time we FORCE the adversarial
review (MR_ROBOT_FORCE_FALSIFIER=1) to show the full loop end-to-end.
```

**Terminal:**
```bash
head -10 "$CYBERSEC_LAB/test-corpus/malicious/bind_shell.py"
```

**Caption B (during run):**
```
Triage (gpt-oss-120b) → MALICIOUS → Falsifier (Nemotron-3-Ultra) audits it.
Heterogeneous auditor (ΔA=1.0) → the verdict SURVIVES the challenge (upheld, not overturned).
Had the falsifier returned FALSIFIED, MR. Robot re-runs with the counter-argument
(max 2 iterations). That genuine verdict-flip path is exercised by
tests/test_orchestrator_audit.py::test_self_correction_flip_recorded.
```

**Terminal:**
```bash
MR_ROBOT_FORCE_FALSIFIER=1 python triage_orchestrator.py \
  "$CYBERSEC_LAB/test-corpus/malicious/bind_shell.py" 2>/dev/null \
  | jq '{
      verdict: .final_verdict,
      propagator: ._meta.propagator_family,
      auditor: ._meta.auditor_family,
      kinship_lock_risk: ._meta.kinship_lock_risk,
      history: [.correction_history[] | {iter: .iteration, status: .falsifier_status, auditor: .heterogeneity.auditor_family, dist: .heterogeneity.architectural_distance}]
    }'
```

**Caption C:**
```
Verdict: MALICIOUS — SURVIVED adversarial review by a heterogeneous auditor (ΔA=1.0).
Every step is in the audit trail; a real verdict flip is logged as a
self_correction row (verdict_before → verdict_after) when the falsifier wins.
```

---

## Scene 8 — Accuracy report (honest metrics)  (3:40 – 4:15, 35s)

**Caption A:**
```
Real numbers: 135 malicious + 38 benign = 173 ground-truth samples.
```

**Terminal:**
```bash
jq '{
  accuracy: .metrics.accuracy,
  precision: .metrics.precision,
  recall: .metrics.recall,
  f1: .metrics.f1,
  fpr: .metrics.fpr,
  confusion_matrix: .metrics.confusion_matrix
}' docs/accuracy_report.json
```

**Caption B:**
```
Recall 100% — no malicious sample missed.
Precision 99.26%, FPR 2.63% — 1 false positive on 38 benign samples.
Honest benchmark: 10% exact-match on CyberSOCEval (public, reproducible).
```

---

## Scene 9 — Audit trail (SANS requirement #8)  (4:15 – 4:40, 25s)

**Caption:**
```
Every tool call is logged: tool, inputs, verdict, ΔA, kinship-lock flag.
SQLite WAL — concurrent-safe — JSON-exportable for submission.
```

**Terminal:**
```bash
sqlite3 logs/audit_trail.db <<SQL
.headers on
.mode column
SELECT tool_name, verdict, confidence, duration_ms
FROM executions
ORDER BY id DESC
LIMIT 5;
SQL
```

---

## Scene 10 — Closing card  (4:40 – 5:00, 20s)

**Caption (centered):**
```
github.com/Grizaceo/mr-robot-adversarial
Built for SANS FIND EVIL! 2026
MIT license — try-it-out: docs/try_it_out.md
```

**Terminal:**
```bash
clear
figlet -f small "thanks"
echo
echo "Repo:  https://github.com/Grizaceo/mr-robot-adversarial"
echo "Guide: docs/try_it_out.md"
```

---

## Captions track (SRT, drop into video editor)

If you prefer baked-in subtitles instead of OBS text sources, save the file
`demo/video_captions.srt` (also in this repo) and import as a subtitle track
in DaVinci Resolve / Premiere / Kdenlive.

## Timing summary

| Scene | In   | Out  | Duration |
|-------|------|------|----------|
| 1 Title | 0:00 | 0:08 | 8s |
| 2 Problem | 0:08 | 0:25 | 17s |
| 3 Architecture | 0:25 | 0:50 | 25s |
| 4 Health | 0:50 | 1:05 | 15s |
| 5 Malicious | 1:05 | 2:00 | 55s |
| 6 Benign | 2:00 | 2:45 | 45s |
| 7 Adversarial review | 2:45 | 3:40 | 55s |
| 8 Metrics | 3:40 | 4:15 | 35s |
| 9 Audit trail | 4:15 | 4:40 | 25s |
| 10 Closing | 4:40 | 5:00 | 20s |
| **Total** | | | **5:00** |

Budget ~10-15s of slack — if a scene runs over, trim Scene 3 first (architecture
is the easiest to compress with a smaller `sed` range).
